# ksdump_run7.py - hook keystore2 AES-GCM, then drive a REAL signing via mint4.
import json
import os
import subprocess
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'ksdump_capture7.json')
SCRIPT = os.path.join(HERE, 'agent', 'ksdump8.js')
OFF = {'AES_gcm_decrypt': 0x71b8, 'AES_gcm_encrypt': 0x71b0}

js = open(SCRIPT, encoding='utf-8').read()
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
        if t in ('base', 'hooked', 'ready', 'err', 'sym'):
            print('[%s] %s' % (t, str(p)[:150]), flush=True)
        elif t == 'hmac_key':
            print('[KS HMAC KEY] len=%s key=%s hex64=%s'
                  % (p.get('klen'), p.get('key'), p.get('hex64')), flush=True)
        elif t == 'hmac_upd':
            print('[KS upd] len=%s %s' % (p.get('len'), str(p.get('data'))[:70]), flush=True)
        elif t == 'hmac_final':
            print('[KS H] %s' % p.get('out'), flush=True)
        elif t == 'digest_upd':
            print('[KS digest] len=%s %s' % (p.get('len'), str(p.get('data'))[:70]), flush=True)
        elif t == 'call':
            print('[call] %s %s' % (p.get('fn'), p.get('phase')), flush=True)
    elif m.get('type') == 'error':
        print('[!]', str(m)[:200], flush=True)


scr = sess.create_script(js)
scr.on('message', on_msg)
scr.load()
time.sleep(2)
print('[*] launching the app-signing driver (mint4_run.py)...', flush=True)
proc = subprocess.Popen([sys.executable, '-X', 'utf8',
                         os.path.join(HERE, 'mint4_run.py')],
                        stdout=open(os.path.join(HERE, 'ksdump_mint4.log'), 'w'),
                        stderr=subprocess.STDOUT)
n_calls = 0
for i in range(34):
    time.sleep(2)
    n_calls = len([e for e in events if e.get('t') == 'call'])
    if i % 3 == 0:
        print('   t=%2ds calls=%d' % (2 * (i + 1), n_calls), flush=True)
    if n_calls >= 8:
        break
json.dump(events, open(OUT, 'w'), indent=1)
print('saved', OUT, '| events:', len(events), '| calls:', n_calls)
try:
    proc.terminate()
except Exception:
    pass
sess.detach()