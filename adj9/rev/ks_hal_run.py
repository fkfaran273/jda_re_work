# ks_hal_run.py - key2 capture, now targeted at the process the DB proved is
# the owner of key2's KeyMint instance (km_uuid 000...001 == keystore_cli_v2's
# "tee" instance): the vendor HAL android.hardware.keymaster@4.1-service-qti.
#
# Two independent triggers, neither of which needs a flaky app attach:
#   (0) keystore_cli_v2 generate/sign-verify at seclevel=tee -> proves which
#       process performs Linux-side crypto for HAL keys at all (digest hooks).
#   (1) the app's own signing burst (force-stop + start cycles).
# keystore2 is hooked too, as the fallback hypothesis.
import json
import os
import subprocess
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'ks_hal_capture.json')
SWEEP = open(os.path.join(HERE, 'agent', 'ks_sweep.js'), encoding='utf-8').read()
APP = 'com.penti.app'

CAND = ['android.hardware.keymaster@4.1-service-qti', 'keystore2',
        'credstore', 'TrickyStore']
result = {'targets': {}, 'events': {}, 'app': []}


def sh(cmd, timeout=40):
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


def wait_frida(timeout=25):
    """The previous run's keystore2 attach failed first because frida-server was
    still coming up; poll until the device actually answers before attaching."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
            dev.enumerate_processes()
            print('frida ready after %.1fs' % (time.time() - t0), flush=True)
            return dev
        except Exception as e:
            print('  waiting for frida-server: %s' % str(e)[:70], flush=True)
            time.sleep(1.5)
    raise SystemExit('frida-server never became ready')


FIRE = ('hmac_key', 'hmac1shot')


def mk_on_msg(ev, nm):
    def on_msg(m, data):
        if m.get('type') != 'send':
            print('[%s !] %s' % (nm, str(m)[:200]), flush=True)
            return
        p = m.get('payload', {})
        ev.append(p)
        t = p.get('t')
        if t == 'ready':
            print('[%s ready] mods=%s' % (nm, p.get('mods')), flush=True)
        elif t == 'hooked':
            print('  [%s hook] %-16s %s' % (nm, p.get('name'), p.get('mod')), flush=True)
        elif t == 'hmac_key':
            print('*** [%s HMAC KEY] klen=%s key=%s hex64=%s'
                  % (nm, p.get('klen'), p.get('key'), p.get('hex64')), flush=True)
        elif t == 'hmac1shot':
            print('*** [%s 1SHOT] key=%s len=%s data=%s'
                  % (nm, p.get('key'), p.get('len'), str(p.get('data'))[:60]),
                  flush=True)
        elif t == 'hmac_final':
            print('*** [%s HMAC H] %s' % (nm, p.get('out')), flush=True)
        elif t == 'hmac_upd':
            print('    [%s upd] len=%s %s'
                  % (nm, p.get('len'), str(p.get('data'))[:60]), flush=True)
        elif t == 'digest_upd':
            print('    [%s digest] len=%s %s'
                  % (nm, p.get('len'), str(p.get('data'))[:60]), flush=True)
    return on_msg


def fired():
    return any(e.get('t') in FIRE
               for evs in result['events'].values() for e in evs)


def digest_seen():
    return any(e.get('t') == 'digest_upd'
               for evs in result['events'].values() for e in evs)


def main():
    restart_frida()
    dev = wait_frida()

    # ---- attach sweep to every candidate, with retries (the race that killed
    #      the previous run's keystore2 session is gone now) -------------------
    sessions = {}
    for name in CAND:
        for pid in pidof(name):
            for attempt in range(3):
                try:
                    sess = dev.attach(pid)
                    evs = []
                    result['events'][str(pid)] = evs
                    result['targets'][str(pid)] = name
                    scr = sess.create_script(SWEEP)
                    scr.on('message', mk_on_msg(evs, name))
                    scr.load()
                    sessions[pid] = sess
                    break
                except Exception as e:
                    print('[!] attach %s(%d) try%d: %s'
                          % (name, pid, attempt + 1, str(e)[:90]), flush=True)
                    time.sleep(1.0)
    time.sleep(1)
    print('hooks live in: %s' % result['targets'], flush=True)

    # ---- trigger 0: controlled keystore op via keystore_cli_v2 --------------
    print('\n--- trigger 0: keystore_cli_v2 (seclevel=tee) controlled op ---',
          flush=True)
    sh('keystore_cli_v2 delete --name=det_cli')
    sh('keystore_cli_v2 generate --name=det_cli --seclevel=tee 2>&1 | head -2')
    sh('keystore_cli_v2 sign-verify --name=det_cli 2>&1 | head -4')
    time.sleep(2)
    print('digest hooks fired by CLI op: %s' % digest_seen(), flush=True)

    # ---- trigger 1: the app's own signing burst (no app attach) ------------
    print('\n--- trigger 1: app signing cycles ---', flush=True)
    for i in range(8):
        if fired():
            break
        sh("/debug_ramdisk/su -c 'am force-stop %s'" % APP)
        time.sleep(0.8)
        sh('am start -n com.penti.app/.ui.main.MainActivity')
        time.sleep(5)
        if fired():
            break
        sh('input keyevent KEYCODE_HOME')
        time.sleep(2.5)
        print('  cycle %d: fired=%s' % (i + 1, fired()), flush=True)

    # ---- verdict ------------------------------------------------------------
    json.dump(result, open(OUT, 'w'), indent=1)
    print('\n==== VERDICT ====', flush=True)
    any_fire = False
    for pid_s, evs in result['events'].items():
        keys = [e for e in evs if e.get('t') in FIRE]
        digs = [e for e in evs if e.get('t') == 'digest_upd']
        if keys:
            any_fire = True
            print('  %s (%s): %d HMAC key events'
                  % (pid_s, result['targets'][pid_s], len(keys)), flush=True)
            for e in keys[:4]:
                print('    %s' % json.dumps(e)[:190], flush=True)
        if digs:
            print('  %s (%s): %d digest_upd events (Linux-side crypto here)'
                  % (pid_s, result['targets'][pid_s], len(digs)), flush=True)
    if not any_fire:
        print('  no HMAC key captured. inventories:', flush=True)
        for pid_s, evs in result['events'].items():
            print('    %s (%s): %s'
                  % (pid_s, result['targets'][pid_s],
                     [e.get('name') for e in evs if e.get('t') == 'hooked']),
                  flush=True)
    print('saved', OUT, flush=True)
    for sess in sessions.values():
        try:
            sess.detach()
        except Exception:
            pass


if __name__ == '__main__':
    main()