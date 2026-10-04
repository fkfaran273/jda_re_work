# ks_ks2_run.py - key2 capture with the real target finally known.
#
# Provider enumeration on the device proved the SDK's Mac.getInstance("HmacSHA256")
# resolves, for a keystore key, to
#     AndroidKeyStoreBCWorkaround -> android.security.keystore2.AndroidKeyStoreHmacSpi
# i.e. the MAC is executed THROUGH keystore2 (binder), not in the app: that is
# why the app's libcrypto, Conscrypt's NativeCrypto and the vendor HAL all
# showed zero HMAC activity. keystore2 is therefore the process to hook - and it
# is also the one that keeps RESTARTING (11561 -> 4268 -> 9857 -> ...), which is
# why every previous keystore2 hook silently expired before the MAC happened.
#
# Strategy: keep the app attached + hooks loaded, watch keystore2 in a background
# thread and re-install the minimal hooks on every new pid, and only THEN load
# the Java probe so the guaranteed HMAC runs while the hooks are definitely live.
import hashlib
import hmac
import json
import os
import subprocess
import threading
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'ks_ks2_capture.json')
MIN = open(os.path.join(HERE, 'agent', 'ks_min.js'), encoding='utf-8').read()
PROBE = open(os.path.join(HERE, 'agent', 'ks_probe_bundle.js'),
             encoding='utf-8').read()
APP = 'com.penti.app'
result = {'ks2': {}, 'app_hooks': [], 'app': [], 'ks2_pids': []}
stop = threading.Event()


def sh(cmd, timeout=40):
    return subprocess.run(['adb', 'shell', cmd], capture_output=True, text=True,
                          timeout=timeout).stdout


def pid1(name):
    p = sh('pidof %s' % name).strip().split()
    return int(p[0]) if p and p[0].isdigit() else 0


def restart_frida():
    subprocess.run(['adb', 'shell',
                    "/debug_ramdisk/su -c 'pkill -9 frs64; pkill -9 fs17root'"],
                   capture_output=True)
    time.sleep(1)
    subprocess.Popen(['adb', 'shell',
                      "/debug_ramdisk/su -c 'exec /data/local/tmp/fs17root'"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.5)
    subprocess.run(['adb', 'forward', 'tcp:27042', 'tcp:27042'], capture_output=True)


def wait_frida(timeout=30):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
            dev.enumerate_processes()
            return dev
        except Exception:
            time.sleep(1.5)
    raise SystemExit('frida-server unavailable')


def ks_msg_factory(ev, tag):
    def on_msg(m, data):
        if m.get('type') != 'send':
            return
        p = m.get('payload', {})
        ev.append(p)
        t = p.get('t')
        if t == 'hmac_key':
            print('***** [%s KEY] via=%s klen=%s key=%s hex64=%s'
                  % (tag, p.get('via'), p.get('klen'), p.get('key'), p.get('hex64')),
                  flush=True)
        elif t == 'hmac_final':
            print('***** [%s H] %s' % (tag, p.get('out')), flush=True)
        elif t == 'digsign_init' and p.get('has_key'):
            print('***** [%s DIGSIGN] mod=%s pkey=%s'
                  % (tag, p.get('mod'), p.get('pkey')), flush=True)
        elif t == 'digest_call':
            if len([x for x in ev if x.get('t') == 'digest_call']) <= 12:
                print('    [%s CALL] %s @ %s' % (tag, p.get('fn'), p.get('mod')),
                      flush=True)
        elif t in ('ready', 'err'):
            print('[%s %s] %s' % (tag, t, str(p)[:150]), flush=True)
    return on_msg


def main():
    restart_frida()
    dev = wait_frida()
    print('frida ready', flush=True)

    # ---- app: attach first (its guard requires the early window) ------------
    appsess = None
    for outer in range(8):
        sh("/debug_ramdisk/su -c 'am force-stop %s'" % APP)
        time.sleep(0.4)
        sh('am start -n com.penti.app/.ui.main.MainActivity')
        apid, t0 = 0, time.time()
        while time.time() - t0 < 8 and not apid:
            apid = pid1(APP)
            time.sleep(0.05)
        if not apid:
            continue
        try:
            appsess = dev.attach(apid)
            print('[outer %d] app attach OK pid=%d' % (outer + 1, apid), flush=True)
            break
        except Exception as e:
            print('[!] outer %d attach: %s' % (outer + 1, str(e)[:80]), flush=True)
            time.sleep(1.0)

    # ---- watcher: survive keystore2 restarts AND cover the vendor HAL -------
    # km_uuid 000...0001 is the device's only (TEE) KeyMint instance and
    # keystore2 reaches it through libkm_compat_service -> the legacy
    # keymaster@4.1 HAL process, which maps its own libcrypto. Both must be
    # instrumented while the HMAC runs.
    ks2_sessions = {}
    WATCH = ['keystore2', 'android.hardware.keymaster@4.1-service-qti']

    def watch():
        cur = {}
        while not stop.is_set():
            for name in WATCH:
                try:
                    pid = pid1(name)
                except Exception:
                    pid = 0
                if pid and cur.get(name) != pid:
                    try:
                        s = dev.attach(pid)
                        ev = []
                        tag = '%s:%d' % (name.split('.')[-1], pid)
                        result['ks2'][tag] = ev
                        result['ks2_pids'].append(pid)
                        scr = s.create_script(MIN)
                        scr.on('message', ks_msg_factory(ev, tag))
                        scr.load()
                        ks2_sessions[pid] = s
                        cur[name] = pid
                        print('[watcher] hooked %s pid=%d' % (name, pid), flush=True)
                    except Exception as e:
                        print('[watcher] %s attach %d failed: %s'
                              % (name, pid, str(e)[:70]), flush=True)
            time.sleep(0.4)
    th = threading.Thread(target=watch, daemon=True)
    th.start()
    time.sleep(2.5)   # let the watcher install hooks before the MAC is triggered

    # ---- NOW load the probe: the HMAC fires with keystore2 hooks live -------
    if appsess is not None:
        aev = []
        result['app_hooks'] = aev
        ascr = appsess.create_script(MIN)
        ascr.on('message', ks_msg_factory(aev, 'app'))
        ascr.load()

        def app_msg(m, data):
            if m.get('type') != 'send':
                print('[APP !] %s' % str(m)[:200], flush=True)
                return
            p = m.get('payload', {})
            result['app'].append(p)
            t = p.get('t')
            if t == 'keybytes':
                print('***** [APP keybytes] %s' % p.get('hex'), flush=True)
            elif t == 'mac':
                print('***** [APP MAC] %s' % str(p)[:220], flush=True)
            elif t == 'nc':
                print('***** [SPI-CALL] %s.%s(%s) args=%s'
                      % (str(p.get('cls', '')).split('.')[-1], p.get('m'),
                         p.get('sig'), p.get('a')), flush=True)
            elif t in ('probe',) and p.get('step') in (
                    'default Mac provider', 'SPI implementation', 'key_encoded',
                    'hookedNamed ' + str(p.get('v'))):
                print('[APP] %s' % str(p)[:220], flush=True)
        pscr = appsess.create_script(PROBE)
        pscr.on('message', app_msg)
        pscr.load()
        print('probe loaded (MAC under live keystore2 hooks)', flush=True)
    else:
        print('APP ATTACH FAILED', flush=True)

    for _ in range(20):
        time.sleep(1)
        if any(e.get('t') == 'hmac_key'
               for evs in result['ks2'].values() for e in evs):
            break
    stop.set()
    time.sleep(0.3)

    # ---- verdict + validation ----------------------------------------------
    json.dump(result, open(OUT, 'w'), indent=1)
    print('\n==== VERDICT ====', flush=True)
    keys = []
    for tag, evs in result['ks2'].items():
        for e in evs:
            if e.get('t') == 'hmac_key':
                keys.append((tag, e))
            elif e.get('t') == 'hmac_final':
                print('  MAC in %s = %s' % (tag, e.get('out')), flush=True)
    for p in result['app']:
        if p.get('t') == 'keybytes' and p.get('hex'):
            keys.append(('app:getEncoded', {'via': 'getEncoded', 'key': p['hex'],
                                            'klen': p.get('len')}))
    for where, e in keys:
        print('  KEY from %s via %s: klen=%s key=%s'
              % (where, e.get('via'), e.get('klen'), e.get('key')), flush=True)
    if keys:
        khex = keys[0][1].get('key') or ''
        if khex and khex not in ('n/a', 'ERR') and len(khex) % 2 == 0:
            kb = bytes.fromhex(khex)
            for p in result['app']:
                if p.get('t') == 'mac':
                    for f in ('def_provider', 'ks_provider'):
                        got = p.get(f) or ''
                        if len(got) == 64:
                            exp = hmac.new(kb, p['msg'].encode(),
                                           hashlib.sha256).hexdigest()
                            print('  VALIDATE %-12s msg=%r %s'
                                  % (f, p['msg'],
                                     'KEY2 CONFIRMED' if exp == got else 'differs'),
                                  flush=True)
    else:
        print('  no key captured. keystore2 hook inventories:', flush=True)
        for pid_s, evs in result['ks2'].items():
            print('    ks2:%s -> %s' % (pid_s, [e.get('name') for e in evs
                                                if e.get('t') == 'hooked']),
                  flush=True)
    print('keystore2 sessions: %s' % sorted(result['ks2'].keys()), flush=True)
    print('saved', OUT, flush=True)
    for s in ks2_sessions.values():
        try:
            s.detach()
        except Exception:
            pass
    if appsess is not None:
        try:
            appsess.detach()
        except Exception:
            pass


if __name__ == '__main__':
    main()