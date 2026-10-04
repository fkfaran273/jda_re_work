# ks_sweep_run.py - ONE SHOT key2 extraction, process-agnostic.
#
# The earlier attempt hooked ONLY keystore2 and captured 0 HMAC calls even
# though the app-side probe produced real MACs. That proves the AndroidKeyStore
# HMAC for key2 is served by a DIFFERENT process on this device. So we now
# install the sweep hooks into every candidate crypto process at once, then
# drive a guaranteed keystore HMAC from inside the app (UID 10350) with the
# SDK's own alias "key2". Whichever process fires is the backend; HMAC_Init_ex
# gives key2's raw bytes and HMAC_Final gives H itself (self-validating).
import json
import os
import subprocess
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'ks_sweep_capture.json')
SWEEP = open(os.path.join(HERE, 'agent', 'ks_sweep.js'), encoding='utf-8').read()
PROBE = os.path.join(HERE, 'agent', 'ks_sweep_probe.js')
APP = 'com.penti.app'

CAND_NAMES = ['keystore2', 'android.hardware.keymaster@4.1-service-qti',
              'credstore', 'TrickyStore',
              'android.hardware.gatekeeper@1.0-service-qti']

result = {'targets': {}, 'events': {}, 'app': [], 'pids': {}}


def sh(cmd, timeout=30):
    return subprocess.run(['adb', 'shell', cmd], capture_output=True, text=True,
                          timeout=timeout).stdout


def pidof(name):
    out = sh('pidof %s' % name).strip().split()
    return [int(x) for x in out if x.isdigit()]


def restart_frida():
    subprocess.run(['adb', 'shell',
                    "/debug_ramdisk/su -c 'pkill -9 frs64; pkill -9 fs17root'"],
                   capture_output=True)
    time.sleep(1)
    subprocess.Popen(['adb', 'shell',
                      "/debug_ramdisk/su -c 'exec /data/local/tmp/fs17root'"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    subprocess.run(['adb', 'forward', 'tcp:27042', 'tcp:27042'], capture_output=True)


def mk_on_msg(ev, nm):
    def on_msg(m, data):
        if m.get('type') != 'send':
            print('[%s !] %s' % (nm, str(m)[:200]), flush=True)
            return
        p = m.get('payload', {})
        ev.append(p)
        t = p.get('t')
        if t in ('ready', 'err'):
            print('[%s %s] %s' % (nm, t, str(p)[:170]), flush=True)
        elif t == 'hmac_key':
            print('*** [%s HMAC KEY] klen=%s key=%s hex64=%s'
                  % (nm, p.get('klen'), p.get('key'), p.get('hex64')), flush=True)
        elif t == 'hmac_final':
            print('*** [%s HMAC H] %s' % (nm, p.get('out')), flush=True)
        elif t == 'hmac_upd':
            print('    [%s upd] len=%s %s'
                  % (nm, p.get('len'), str(p.get('data'))[:70]), flush=True)
        elif t == 'hmac1shot':
            print('*** [%s 1SHOT] key=%s len=%s data=%s'
                  % (nm, p.get('key'), p.get('len'), str(p.get('data'))[:60]),
                  flush=True)
        elif t == 'digest_upd':
            print('    [%s digest] len=%s %s'
                  % (nm, p.get('len'), str(p.get('data'))[:70]), flush=True)
    return on_msg


def main():
    restart_frida()
    dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')

    targets = {}
    for name in CAND_NAMES:
        for pid in pidof(name):
            targets[pid] = name
    print('candidate processes: %s' % targets, flush=True)
    result['pids'] = {str(k): v for k, v in targets.items()}

    sessions = {}
    for pid, name in targets.items():
        try:
            sess = dev.attach(pid)
            scr = sess.create_script(SWEEP)
            events = []
            result['events'][str(pid)] = events
            scr.on('message', mk_on_msg(events, name))
            scr.load()
            sessions[pid] = (sess, scr)
            result['targets'][str(pid)] = name
        except Exception as e:
            print('[!] sweep attach %s(%d): %s' % (name, pid, str(e)[:120]), flush=True)
    time.sleep(1)

    # ---------- 2. drive a guaranteed keystore HMAC from inside the app -------
    def app_msg(m, data):
        if m.get('type') != 'send':
            print('[app !] %s' % str(m)[:220], flush=True)
            return
        p = m.get('payload', {})
        result['app'].append(p)
        print('[app] %s' % str(p)[:280], flush=True)

    appsess = None
    sh("/debug_ramdisk/su -c 'am force-stop %s'" % APP)
    time.sleep(1)
    sh('am start -n com.penti.app/.ui.main.MainActivity')
    pid = 0
    for _ in range(40):
        pid = int((sh('pidof %s' % APP).strip().split() or [0])[0])
        if pid:
            break
        time.sleep(0.3)
    print('app pid', pid, flush=True)
    for _ in range(10):
        try:
            appsess = dev.attach(pid)
            break
        except Exception as e:
            print('[!] app attach retry: %s' % str(e)[:100], flush=True)
            time.sleep(0.7)
            pid = int((sh('pidof %s' % APP).strip().split() or [0])[0])
            if not pid:
                sh('am start -n com.penti.app/.ui.main.MainActivity')
                time.sleep(0.6)
                pid = int((sh('pidof %s' % APP).strip().split() or [0])[0])
    if appsess is not None:
        appscr = appsess.create_script(open(PROBE, encoding='utf-8').read())
        appscr.on('message', app_msg)
        appscr.load()
        for _ in range(25):
            time.sleep(1)
            if any(p.get('t') == 'mac' for p in result['app']):
                break
        time.sleep(3)
    else:
        print('could not attach to app', flush=True)

    # ---------- 3. verdict ---------------------------------------------------
    json.dump(result, open(OUT, 'w'), indent=1)
    print('\n==== VERDICT ====', flush=True)
    winner = None
    for pid_s, evs in result['events'].items():
        keys = [e for e in evs if e.get('t') in ('hmac_key', 'hmac1shot')]
        if keys:
            winner = (pid_s, result['targets'].get(pid_s, '?'))
            print('  process %s (%s) captured %d HMAC key events'
                  % (pid_s, winner[1], len(keys)), flush=True)
            for e in keys[:6]:
                print('    %s' % json.dumps(e)[:200], flush=True)
    if not winner:
        print('  NO process fired. hook inventory per process:', flush=True)
        for pid_s, evs in result['events'].items():
            syms = [e.get('name') for e in evs if e.get('t') == 'hooked']
            print('    %s (%s): %s'
                  % (pid_s, result['targets'].get(pid_s, '?'), syms), flush=True)
    print('saved', OUT, flush=True)

    for sess, _ in sessions.values():
        try:
            sess.detach()
        except Exception:
            pass
    if appsess is not None:
        try:
            appsess.detach()
        except Exception:
            pass


if __name__ == '__main__':
    main()