# ks_freeze_test.py - WHICH PROCESS actually computes the key2 HMAC?
#
# Nobody's exported HMAC/EVP symbol fires when the app MACs with key2, yet the
# MAC is real (Conscrypt's AndroidKeyStoreHmacSpi -> keystore). So the work is
# done by internal (statically linked / non-exported) code in some service
# process. This test identifies that process by SIGSTOPping a candidate and
# watching whether the app-side MAC still completes:
#   * MAC blocks/fails while X is frozen  -> X computes it (or is on the path)
#   * MAC still returns instantly         -> X is not involved
import json
import os
import subprocess
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'ks_freeze_result.json')
PROBE = open(os.path.join(HERE, 'agent', 'ks_probe_bundle.js'),
             encoding='utf-8').read()
APP = 'com.penti.app'
CAND = {'keystore2': 'keystore2',
        'hal': 'android.hardware.keymaster@4.1-service-qti'}
result = {}


def sh(cmd, timeout=40):
    return subprocess.run(['adb', 'shell', cmd], capture_output=True, text=True,
                          timeout=timeout).stdout


def pid1(name):
    p = sh('pidof %s' % name).strip().split()
    return int(p[0]) if p and p[0].isdigit() else 0


def su(cmd):
    subprocess.run(['adb', 'shell', "/debug_ramdisk/su -c '%s'" % cmd],
                   capture_output=True)


def restart_frida():
    su('pkill -9 frs64; pkill -9 fs17root')
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


def attach_app(dev):
    for outer in range(8):
        su('am force-stop %s' % APP)
        time.sleep(0.4)
        sh('am start -n com.penti.app/.ui.main.MainActivity')
        apid, t0 = 0, time.time()
        while time.time() - t0 < 8 and not apid:
            apid = pid1(APP)
            time.sleep(0.05)
        if not apid:
            continue
        try:
            s = dev.attach(apid)
            print('  app attach OK pid=%d' % apid, flush=True)
            return s
        except Exception as e:
            print('  attach retry: %s' % str(e)[:70], flush=True)
            time.sleep(1.0)
    return None


def run_probe(sess, label, wait=18):
    """Load the probe and report whether the MAC came back, and how fast."""
    events = []
    done = {'mac': False}

    def on_msg(m, data):
        if m.get('type') != 'send':
            return
        p = m.get('payload', {})
        events.append(p)
        if p.get('t') == 'mac':
            done['mac'] = True
            print('    [%s] MAC -> %s' % (label, str(p)[:150]), flush=True)
        elif p.get('t') == 'probe' and p.get('step') in (
                'SPI implementation', 'key_encoded'):
            print('    [%s] %s' % (label, p.get('step')), flush=True)
        elif p.get('t') == 'err':
            print('    [%s] ERR %s' % (label, str(p)[:160]), flush=True)
    t0 = time.time()
    scr = sess.create_script(PROBE)
    scr.on('message', on_msg)
    scr.load()
    while time.time() - t0 < wait and not done['mac']:
        time.sleep(0.4)
    dt = time.time() - t0
    verdict = ('MAC returned in %.1fs' % dt) if done['mac'] else \
              ('NO MAC within %ds (blocked / blocked-ish)' % wait)
    print('    [%s] %s' % (label, verdict), flush=True)
    try:
        scr.unload()
    except Exception:
        pass
    return {'mac': done['mac'], 'seconds': round(dt, 2), 'events': events}


def main():
    restart_frida()
    dev = wait_frida()
    print('frida ready', flush=True)
    sess = attach_app(dev)
    if sess is None:
        print('APP ATTACH FAILED', flush=True)
        return

    # baseline first: unfrozen
    print('\n=== phase baseline (nothing frozen) ===', flush=True)
    result['baseline'] = run_probe(sess, 'baseline')

    for label, proc in CAND.items():
        pid = pid1(proc)
        if not pid:
            print('\n=== phase %s: %s not running ===' % (label, proc), flush=True)
            continue
        print('\n=== phase %s: SIGSTOP %s (pid %d) ===' % (label, proc, pid),
              flush=True)
        su('kill -STOP %d' % pid)
        time.sleep(0.5)
        result[label] = run_probe(sess, label)
        su('kill -CONT %d' % pid)
        time.sleep(0.5)
        print('  resumed %s' % proc, flush=True)

    # and a final baseline again, to prove the app is still healthy
    print('\n=== phase baseline2 (all resumed) ===', flush=True)
    result['baseline2'] = run_probe(sess, 'baseline2')

    json.dump(result, open(OUT, 'w'), indent=1)
    print('\n==== SUMMARY ====', flush=True)
    for k, v in result.items():
        print('  %-10s mac=%s  %.1fs' % (k, v['mac'], v['seconds']), flush=True)
    print('saved', OUT, flush=True)
    try:
        sess.detach()
    except Exception:
        pass


if __name__ == '__main__':
    main()