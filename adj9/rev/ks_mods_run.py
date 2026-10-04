# ks_mods_run.py - enumerate modules/crypto exports of keystore2 and the
# keymaster HAL process: where does the KeyMint blob crypto live?
import json
import os
import subprocess
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
JS = open(os.path.join(HERE, 'agent', 'ks_mods.js'), encoding='utf-8').read()
subprocess.run(['adb', 'forward', 'tcp:27042', 'tcp:27042'], capture_output=True)
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')

targets = []
for nm in ('keystore2', 'android.hardware.keymaster@4.1-service-qti'):
    out = subprocess.run(['adb', 'shell', 'pidof', nm], capture_output=True,
                         text=True).stdout.strip()
    if out:
        targets.append((nm, int(out.split()[0])))
print('targets:', targets, flush=True)

for nm, pid in targets:
    print('\n=========== %s (pid %d) ===========' % (nm, pid), flush=True)
    try:
        sess = dev.attach(pid)
    except Exception as e:
        print('attach failed:', e, flush=True)
        continue
    res = {}

    def on_msg(m, data):
        if m.get('type') == 'send':
            p = m.get('payload', {})
            res[p.get('t')] = p
        elif m.get('type') == 'error':
            print('[!]', str(m)[:200], flush=True)

    scr = sess.create_script(JS)
    scr.on('message', on_msg)
    scr.load()
    time.sleep(4)
    if 'mods' in res:
        print('modules (%d):' % res['mods']['n'], flush=True)
        for line in res['mods']['list']:
            print('   ', line, flush=True)
    if 'crypto' in res:
        print('crypto-ish exports: %d' % res['crypto']['n'], flush=True)
        for line in res['crypto']['list']:
            print('   ', line, flush=True)
    sess.detach()