# ksdump_run.py - extract the key2 HMAC material by hooking keystore2's AES-GCM
# unwrap (offline: local attach only, no server traffic).
import json
import os
import subprocess
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'ksdump_capture.json')
SCRIPT = os.path.join(HERE, 'agent', 'ksdump.js')

subprocess.run(['adb', 'forward', 'tcp:27042', 'tcp:27042'],
               capture_output=True)
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
pid = int(subprocess.run(['adb', 'shell', 'pidof', 'keystore2'],
                         capture_output=True, text=True).stdout.strip())
print('keystore2 pid =', pid)
sess = dev.attach(pid)
print('attached')
events = []


def on_msg(m, data):
    if m.get('type') == 'send':
        p = m.get('payload', {})
        events.append(p)
        t = p.get('t')
        if t == 'sym':
            print('[sym] %-16s %s %s' % (p.get('name'), p.get('addr'), p.get('mod')))
        elif t == 'hooked':
            print('[hooked]', p.get('name'))
        elif t == 'gcm':
            print('[gcm] %s %s ret=%s' % (p.get('fn'), p.get('phase'), p.get('ret')))
        elif t == 'ready':
            print('[ready]')
        else:
            print('[ev]', str(p)[:200])
    elif m.get('type') == 'error':
        print('[!]', str(m)[:400])


scr = sess.create_script(open(SCRIPT, encoding='utf-8').read())
scr.on('message', on_msg)
scr.load()
time.sleep(2)
print('[*] now triggering a real signing (launching the app)...')
subprocess.run(['adb', 'shell', 'monkey', '-p', 'com.penti.app',
                '-c', 'android.intent.category.LAUNCHER', '1'],
               capture_output=True)
for i in range(24):
    time.sleep(2)
    gcm = [e for e in events if e.get('t') == 'gcm']
    if len(gcm) >= 4:
        print('[*] got %d gcm events, stopping early' % len(gcm))
        break
time.sleep(2)
json.dump(events, open(OUT, 'w'), indent=1)
print('saved', OUT, 'events:', len(events),
      'gcm:', len([e for e in events if e.get('t') == 'gcm']))
sess.detach()
