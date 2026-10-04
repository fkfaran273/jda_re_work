# ksdump_run6.py - hook keystore2's AES-GCM by fixed offset, force a signing.
import json
import os
import subprocess
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'ksdump_capture6.json')
SCRIPT = os.path.join(HERE, 'agent', 'ksdump6.js')
OFF = {'AES_gcm_decrypt': 0x71b8, 'AES_gcm_encrypt': 0x71b0}

js = open(SCRIPT, encoding='utf-8').read()
js = js.replace('var OFF = {};',
                'var OFF = %s;' % json.dumps({k: v for k, v in OFF.items()}))
subprocess.run(['adb', 'forward', 'tcp:27042', 'tcp:27042'], capture_output=True)
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
pid = int(subprocess.run(['adb', 'shell', 'pidof', 'keystore2'],
                         capture_output=True, text=True).stdout.strip())
print('keystore2 pid =', pid, flush=True)
sess = dev.attach(pid)
events = []


def on_msg(m, data):
    if m.get('type') == 'send':
        p = m.get('payload', {})
        events.append(p)
        t = p.get('t')
        if t in ('base', 'hooked', 'ready', 'err'):
            print('[%s] %s' % (t, str(p)[:170]), flush=True)
        elif t == 'call':
            print('[call] %s %s' % (p.get('fn'), p.get('phase')), flush=True)
    elif m.get('type') == 'error':
        print('[!]', str(m)[:300], flush=True)


scr = sess.create_script(js)
scr.on('message', on_msg)
scr.load()
time.sleep(2)
print('[*] fresh install burst: pm clear + launch', flush=True)
subprocess.run(['adb', 'shell', 'pm', 'clear', 'com.penti.app'], capture_output=True)
time.sleep(1)
subprocess.run(['adb', 'shell', 'monkey', '-p', 'com.penti.app',
                '-c', 'android.intent.category.LAUNCHER', '1'], capture_output=True)
n_calls = 0
for i in range(15):
    time.sleep(2)
    n_calls = len([e for e in events if e.get('t') == 'call'])
    print('   t=%2ds calls=%d' % (2 * (i + 1), n_calls), flush=True)
    if n_calls >= 8:
        break
json.dump(events, open(OUT, 'w'), indent=1)
print('saved', OUT, '| events:', len(events), '| calls:', n_calls)
sess.detach()