# attr_read.py - read the app's private AdjustAttribution via the agent's
# readfile RPC. Spawn-based (the guard kills post-launch attaches).
import base64
import json
import sys
import time

HERE = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
sys.path.insert(0, HERE)
import frida

PKG = 'com.penti.app'
AG = HERE + r'\agent\adj9agent.js'

adb = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
pid = adb.spawn([PKG])
sess = adb.attach(pid)
scr = sess.create_script(open(AG, encoding='utf-8').read())
ready = {'ok': False}


def on_msg(m, data):
    p = m.get('payload') if m.get('type') == 'send' else None
    if isinstance(p, dict) and p.get('type') == 'ready':
        ready['ok'] = True
    elif m.get('type') == 'error':
        print('[!]', str(m)[:200])


scr.on('message', on_msg)
scr.load()
adb.resume(pid)
for _ in range(40):
    if ready['ok']:
        break
    time.sleep(0.5)
print('ready', ready['ok'])

# wait for the startup burst to complete (its /attribution lands in the file)
time.sleep(20)
out = scr.exports_sync.readfile('files/AdjustAttribution')
if out.get('ok') and out.get('dataB64'):
    raw = base64.b64decode(out['dataB64'])
    print('AdjustAttribution %d bytes:' % len(raw))
    print(raw.decode('latin1', 'replace')[:900])
else:
    ls = scr.exports_sync.readfile('files')
    print('read failed:', out.get('error'), '| files/:', ls.get('list'))
sess.detach()
