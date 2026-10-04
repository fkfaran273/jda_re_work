# ks_combo_run.py - decisive, self-validating key2 capture.
#
# Open question: WHEN the app computes H = Mac(HmacSHA256, key2), is the MAC
# computed (a) in-process by Conscrypt's libcrypto (app maps libcrypto), or
# (b) as a keystore op inside the vendor keymaster HAL / keystore2?
# Previous runs hooked only keystore2 (0 hits) or only the HAL during an RSA
# op (not an HMAC at all), so neither hypothesis was actually tested.
#
# This run hooks the app AND the HAL AND keystore2 with the minimal, non-hot
# hook set (ks_min.js), then performs a GUARANTEED HMAC from inside the app via
# the SDK's own alias "key2". Whichever process fires is the answer, and the
# captured key is validated in Python against the MAC the probe itself reports.
import hashlib
import hmac
import json
import os
import subprocess
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'ks_combo_capture.json')
MIN = open(os.path.join(HERE, 'agent', 'ks_min.js'), encoding='utf-8').read()
PROBE = os.path.join(HERE, 'agent', 'ks_probe_bundle.js')
APP = 'com.penti.app'
SERVICES = ['android.hardware.keymaster@4.1-service-qti', 'keystore2']
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
    time.sleep(2.5)
    subprocess.run(['adb', 'forward', 'tcp:27042', 'tcp:27042'], capture_output=True)


def wait_frida(timeout=30):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
            dev.enumerate_processes()
            print('frida ready (%.1fs)' % (time.time() - t0), flush=True)
            return dev
        except Exception as e:
            print('  wait frida: %s' % str(e)[:70], flush=True)
            time.sleep(1.5)
    raise SystemExit('frida-server unavailable')


def mk_on_msg(ev, nm):
    def on_msg(m, data):
        if m.get('type') != 'send':
            print('[%s !] %s' % (nm, str(m)[:200]), flush=True)
            return
        p = m.get('payload', {})
        ev.append(p)
        t = p.get('t')
        if t == 'ready':
            print('[%s ready] found=%s pid=%s'
                  % (nm, p.get('found'), p.get('pid')), flush=True)
        elif t == 'hooked':
            print('  [%s hook] %-18s %s' % (nm, p.get('name'), p.get('mod')), flush=True)
        elif t == 'hmac_key':
            print('***** [%s KEY] via=%s klen=%s key=%s hex64=%s'
                  % (nm, p.get('via'), p.get('klen'), p.get('key'),
                     p.get('hex64')), flush=True)
        elif t == 'hmac_final':
            print('***** [%s H] %s' % (nm, p.get('out')), flush=True)
    return on_msg


def fired():
    return any(e.get('t') == 'hmac_key'
               for evs in result['events'].values() for e in evs)


def main():
    restart_frida()
    dev = wait_frida()
    sessions = {}

    def attach(pid, nm):
        for attempt in range(4):
            try:
                sess = dev.attach(pid)
                evs = []
                result['events'][str(pid)] = evs
                result['targets'][str(pid)] = nm
                scr = sess.create_script(MIN)
                scr.on('message', mk_on_msg(evs, nm))
                scr.load()
                sessions[pid] = sess
                print('hook %s pid=%d ok' % (nm, pid), flush=True)
                return sess
            except Exception as e:
                print('[!] attach %s(%d) try%d: %s'
                      % (nm, pid, attempt + 1, str(e)[:90]), flush=True)
                time.sleep(0.9)
        return None

    # ---- 1. the app: one attach, native hooks + the guaranteed HMAC probe ---
    # The app carries an anti-tamper guard: a *failed* ptrace attempt makes it
    # self-terminate, so repeated retries against the same pid are useless and
    # a stale pid poisons the loop. Instead, restart the app and attach on the
    # FIRST sighting of its pid (that is the window that has worked), retrying
    # the whole cycle if we lose the race.
    appsess = None
    for outer in range(6):
        sh("/debug_ramdisk/su -c 'am force-stop %s'" % APP)
        time.sleep(0.4)
        sh('am start -n com.penti.app/.ui.main.MainActivity')
        apid, t0 = 0, time.time()
        while time.time() - t0 < 8:
            p = pidof(APP)
            if p:
                apid = p[0]
                break
            time.sleep(0.05)
        if not apid:
            print('[outer %d] app never appeared' % (outer + 1), flush=True)
            continue
        print('[outer %d] app pid %d' % (outer + 1, apid), flush=True)
        try:
            appsess = dev.attach(apid)
            print('app attach OK on outer %d' % (outer + 1), flush=True)
            break
        except Exception as e:
            print('[!] outer %d attach failed: %s' % (outer + 1, str(e)[:90]),
                  flush=True)
            appsess = None
            time.sleep(1.0)

    if appsess is not None:
        aev = []
        result['events']['app'] = aev
        result['targets']['app'] = APP
        ascr = appsess.create_script(MIN)
        ascr.on('message', mk_on_msg(aev, 'APP'))
        ascr.load()
        time.sleep(0.6)

        def app_msg(m, data):
            if m.get('type') != 'send':
                print('[APP java !] %s' % str(m)[:200], flush=True)
                return
            p = m.get('payload', {})
            result['app'].append(p)
            if p.get('t') == 'keybytes':
                print('***** [APP keybytes] len=%s hex=%s'
                      % (p.get('len'), p.get('hex')), flush=True)
            else:
                print('[APP java] %s' % str(p)[:400], flush=True)
        pscr = appsess.create_script(open(PROBE, encoding='utf-8').read())
        pscr.on('message', app_msg)
        pscr.load()
        print('probe loaded - waiting for the guaranteed HMAC', flush=True)
    else:
        print('APP ATTACH FAILED - cannot force a keystore HMAC', flush=True)

    # ---- 2. the service processes -------------------------------------------
    for nm in SERVICES:
        for pid in pidof(nm):
            attach(pid, nm)

    # ---- 3. wait for the HMAC ----------------------------------------------
    for _ in range(20):
        time.sleep(1)
        if fired():
            break
        if any(p.get('t') == 'mac' for p in result['app']) and _ > 6:
            break

    # if the probe somehow did nothing, force the app's own signing burst
    if not fired():
        print('no fire yet -> app signing cycles', flush=True)
        for i in range(3):
            if fired():
                break
            sh("/debug_ramdisk/su -c 'am force-stop %s'" % APP)
            time.sleep(0.8)
            sh('am start -n com.penti.app/.ui.main.MainActivity')
            time.sleep(5)
            print('  cycle %d fired=%s' % (i + 1, fired()), flush=True)

    # ---- 4. verdict + Python self-validation -------------------------------
    json.dump(result, open(OUT, 'w'), indent=1)
    print('\n==== VERDICT ====', flush=True)
    keys = []
    for pid_s, evs in result['events'].items():
        for e in evs:
            if e.get('t') == 'hmac_key':
                keys.append((pid_s, result['targets'].get(pid_s, '?'), e))
            if e.get('t') == 'hmac_final':
                print('  MAC from %s (%s): %s'
                      % (pid_s, result['targets'].get(pid_s, '?'), e.get('out')),
                      flush=True)
    # the app-side Java capture (getEncoded) counts as a key too
    for p in result['app']:
        if p.get('t') == 'keybytes' and p.get('hex'):
            keys.append(('app', APP + ' [java Key.getEncoded]',
                         {'via': 'Key.getEncoded', 'klen': p.get('len'),
                          'key': p.get('hex')}))
        elif p.get('t') == 'nc':
            print('  conscrypt %s.%s(%s) args=%s'
                  % (p.get('cls', '').split('.')[-1], p.get('m'), p.get('sig'),
                     p.get('a')), flush=True)
    if keys:
        for pid_s, nm, e in keys:
            print('  KEY captured in %s (%s) via %s: klen=%s key=%s'
                  % (pid_s, nm, e.get('via'), e.get('klen'), e.get('key')),
                  flush=True)
        # self-validate: HMAC-SHA256(captured key, probe msg) == probe MAC?
        khex = keys[0][2].get('key')
        if khex and khex not in ('n/a', 'ERR'):
            kb = bytes.fromhex(khex)
            for p in result['app']:
                if p.get('t') == 'mac':
                    for field in ('ks_provider', 'def_provider'):
                        got = p.get(field) or ''
                        if len(got) == 64:
                            exp = hmac.new(kb, p['msg'].encode(),
                                           hashlib.sha256).hexdigest()
                            verdict = 'KEY2 CONFIRMED' if exp == got else ''
                            print('  VALIDATE %-13s %s msg=%r %s'
                                  % (field, 'MATCH' if exp == got else 'differs',
                                     p['msg'], verdict), flush=True)
    else:
        print('  no key captured. inventories:', flush=True)
        for pid_s, evs in result['events'].items():
            print('    %s (%s): %s'
                  % (pid_s, result['targets'].get(pid_s, '?'),
                     [e.get('name') for e in evs if e.get('t') == 'hooked']),
                  flush=True)
    print('saved', OUT, flush=True)
    for sess in sessions.values():
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