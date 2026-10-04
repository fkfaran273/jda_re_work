# ks_mods_run2.py - lean module/export probe of keystore2 + keymaster HAL.
import os
import subprocess
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
JS = open(os.path.join(HERE, 'agent', 'ks_mods2.js'), encoding='utf-8').read()
subprocess.run(['adb', 'forward', 'tcp:27042', 'tcp:27042'], capture_output=True)
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')

for nm in ('keystore2', 'android.hardware.keymaster@4.1-service-qti'):
    out = subprocess.run(['adb', 'shell', 'pidof', nm], capture_output=True,
                         text=True).stdout.strip()
    if not out:
        print('=== %s: not running' % nm, flush=True)
        continue
    pid = int(out.split()[0])
    print('\n=========== %s (pid %d) ===========' % (nm, pid), flush=True)
    try:
        sess = dev.attach(pid)
    except Exception as e:
        print('attach failed:', e, flush=True)
        continue
    print('attached', flush=True)

    def on_msg(m, data):
        if m.get('type') != 'send':
            print('[!]', str(m)[:200], flush=True)
            return
        p = m.get('payload', {})
        t = p.get('t')
        if t == 'mods':
            print('modules (%d):' % p['n'], flush=True)
            for line in p['list']:
                print('   ', line, flush=True)
        elif t == 'crypto':
            print('  crypto exports in %s: %d' % (p.get('mod'), p.get('n')), flush=True)
            for line in p['list']:
                print('    ', line, flush=True)
        elif t == 'err':
            print('  [err]', p.get('msg'), flush=True)
        elif t == 'ready':
            print('  ready', flush=True)

    scr = sess.create_script(JS)
    scr.on('message', on_msg)
    scr.load()
    for _ in range(15):
        time.sleep(1)
        try:
            scr.exports_sync  # touch
        except Exception:
            pass
    sess.detach()