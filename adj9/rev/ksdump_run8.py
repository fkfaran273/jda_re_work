# ksdump_run8.py - extract key2 via libcrypto HMAC hooks inside keystore2.
import json
import os
import subprocess
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'ksdump_capture8.json')
SCRIPT = os.path.join(HERE, 'agent', 'ksdump8.js')

JS = open(SCRIPT, encoding='utf-8').read()
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
        if t in ('sym', 'hooked', 'ready', 'err'):
            print('[%s] %s' % (t, str(p)[:140]), flush=True)
        elif t == 'hmac_key':
            print('[HMAC KEY] len=%s key=%s' % (p.get('klen'), p.get('key')), flush=True)
        elif t == 'hmac_upd':
            print('[HMAC upd] len=%s %s' % (p.get('len'), str(p.get('data'))[:80]), flush=True)
        elif t == 'hmac_final':
            print('[HMAC H] %s' % p.get('out'), flush=True)
        elif t == 'dec_init':
            print('[DEC init] key=%s iv=%s' % (p.get('key'), p.get('iv')), flush=True)
        elif t == 'dec_upd':
            print('[DEC upd] len=%s in=%s' % (p.get('len'), str(p.get('inp'))[:60]), flush=True)
    elif m.get('type') == 'error':
        print('[!]', str(m)[:250], flush=True)


scr = sess.create_script(JS)
scr.on('message', on_msg)
scr.load()
time.sleep(2)
print('[*] fresh-install burst (pm clear + launch) to force real signings', flush=True)
subprocess.run(['adb', 'shell', 'pm', 'clear', 'com.penti.app'], capture_output=True)
time.sleep(1)
subprocess.run(['adb', 'shell', 'monkey', '-p', 'com.penti.app',
                '-c', 'android.intent.category.LAUNCHER', '1'], capture_output=True)
nkey = 0
for i in range(20):
    time.sleep(2)
    nkey = len([e for e in events if e.get('t') == 'hmac_key'])
    if i % 2 == 0:
        print('   t=%2ds hmac_key=%d' % (2 * (i + 1), nkey), flush=True)
    if nkey >= 2:
        break
json.dump(events, open(OUT, 'w'), indent=1)
print('saved', OUT, '| events:', len(events), '| hmac_key:', nkey)
sess.detach()