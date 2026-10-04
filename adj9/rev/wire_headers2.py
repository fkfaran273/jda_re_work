# wire_headers2.py - raw context around /attribution in the dump + saz request blob
import json
import os
import re

P = r'D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin'
raw = open(P, 'rb').read()
for m in list(re.finditer(rb'attribution', raw))[:2]:
    s = max(0, m.start() - 900)
    seg = raw[s:m.start() + 400]
    print('=== context @%d ===' % m.start())
    print(seg.decode('latin1').replace('\x00', '.'))
    print()

S = json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\saz_sessions.json',
                   encoding='utf-8'))
s = [x for x in S if 'attribution' in str(x.get('url'))]
print('=== saz attribution sessions: %d ===' % len(s))
if s:
    x = s[0]
    print('url      : %s' % x['url'])
    print('status   : %s' % x['status'])
    print('auth     : %s' % str(x.get('authorization'))[:200])
    print('request  : %s' % str(x.get('request'))[:800])
    print('params   : %s' % json.dumps(x.get('params'))[:500])
    print('hdr_hex  : %s...' % str(x.get('header_hex'))[:60])