# ksdump_run2.py - extract key2 (HMAC-SHA256) material by hooking keystore2's
# AES-GCM unwrap. Offline: local attach only, no server traffic.
import json
import os
import re
import sqlite3
import subprocess
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'ksdump_capture.json')
DBL = os.path.join(HERE, 'ks_live.sqlite')
SCRIPT = os.path.join(HERE, 'agent', 'ksdump2.js')


def pull_live_key2():
    subprocess.run(['adb', 'shell',
                    "/debug_ramdisk/su -c 'cp /data/misc/keystore/persistent.sqlite "
                    "/data/local/tmp/ks2.sqlite && chmod 666 /data/local/tmp/ks2.sqlite'"],
                   capture_output=True)
    subprocess.run(['adb', 'pull', '/data/local/tmp/ks2.sqlite', DBL],
                   capture_output=True)
    con = sqlite3.connect(DBL)
    cur = con.cursor()
    rows = list(cur.execute(
        'select k.namespace, k.alias, b.id, b.blob from keyentry k '
        'join blobentry b on b.keyentryid = k.id '
        'where b.subcomponent_type = 0 and k.alias = ?', (b'key2',)))
    out = []
    for ns, al, bid, blob in rows:
        b = bytes(blob)
        if not b.startswith(b'pKMblob'):
            continue
        u = b.hex().upper()
        u = u.lower()
        m = re.search(r'844050([0-9a-f]{32})5820([0-9a-f]{64})50([0-9a-f]{32})$', u)
        if m:
            out.append((ns, bid, m.group(1), m.group(2), m.group(3)))
    print('key2 blobs found: %d' % len(out))
    for ns, bid, iv, ct, tag in out:
        print('  ns=%-6s blobentry=%-7s iv=%s' % (ns, bid, iv))
    return out


cands = pull_live_key2()
ivs, cts = [], []
for (_ns, _b, iv, ct, _t) in cands:
    if iv not in ivs:
        ivs.append(iv)
    if ct not in cts:
        cts.append(ct)
iv_js = json.dumps([[int(iv[i:i + 2], 16) for i in range(0, 32, 2)] for iv in ivs])
ct_js = json.dumps([[int(ct[i:i + 2], 16) for i in range(0, 64, 2)] for ct in cts])
js = open(SCRIPT, encoding='utf-8').read()
js = js.replace('var IVS = [[]];', 'var IVS = %s;' % iv_js)
js = js.replace('var CTS = [[]];', 'var CTS = %s;' % ct_js)
run_js = SCRIPT.replace('.js', '_run.js')
open(run_js, 'w', encoding='utf-8').write(js)
print('patterns: %d IVs, %d CTs' % (len(ivs), len(cts)))

subprocess.run(['adb', 'forward', 'tcp:27042', 'tcp:27042'], capture_output=True)
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
        if t in ('sym', 'hooked', 'ready', 'err'):
            print('[%s] %s' % (t, str(p)[:170]))
        elif t == 'gcm':
            print('[gcm] %s %s pat=%s ret=%s'
                  % (p.get('fn'), p.get('phase'), p.get('pat'), p.get('ret')))
    elif m.get('type') == 'error':
        print('[!]', str(m)[:300])


scr = sess.create_script(js)
scr.on('message', on_msg)
scr.load()
time.sleep(2)
print('[*] triggering signings: launching the app...')
subprocess.run(['adb', 'shell', 'monkey', '-p', 'com.penti.app',
                '-c', 'android.intent.category.LAUNCHER', '1'], capture_output=True)
for i in range(20):
    time.sleep(2)
    if len([e for e in events if e.get('t') == 'gcm']) >= 4:
        break
json.dump(events, open(OUT, 'w'), indent=1)
print('saved', OUT, '| events:', len(events),
      '| gcm:', len([e for e in events if e.get('t') == 'gcm']))
sess.detach()