# wire_headers.py - dump the app's GENUINE request headers from the wire dump and
# compare with what our sender emits (Client-SDK, Authorization, User-Agent, ...).
import json
import os
import re

DUMPS = [r'D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin',
         r'D:\advance_emu\ssl_interception\wire_dumps']
found = False
for p in DUMPS[:1]:
    if not os.path.exists(p):
        print('missing dump: %s' % p)
        continue
    found = True
    raw = open(p, 'rb').read()
    print('dump %s  %d B' % (os.path.basename(p), len(raw)))
    for ep in (b'/attribution', b'/session', b'/sdk_click'):
        idxs = [m.start() for m in re.finditer(re.escape(ep), raw)][:3]
        print('\n=== %s : %d occurrences (showing %d) ==='
              % (ep.decode(), len(re.findall(re.escape(ep), raw)), len(idxs)))
        for i in idxs:
            head = raw[max(0, i - 4000): i + 200]
            # find the request line start
            m = re.search(rb'(GET|POST) (/[^ ]*%s[^ ]*) HTTP/1\.[01]\r\n'
                          % re.escape(ep), head)
            if not m:
                continue
            start = max(0, i - 4000) + m.start()
            blk = raw[start:start + 3000]
            end = blk.find(b'\r\n\r\n')
            hdr = blk[:end if end > 0 else 1200]
            print('---- request @%d ----' % start)
            for line in hdr.decode('latin1').split('\r\n'):
                low = line.lower()
                if low.startswith('authorization'):
                    print('   Authorization: %s...[%d chars]'
                          % (line[:110], len(line)))
                elif low.startswith(('get ', 'post ')):
                    print('   %s' % line[:150])
                elif ':' in line:
                    print('   %s' % line[:150])
            print()

print('=== saz_sessions.json: does it carry request headers? ===')
p = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\saz_sessions.json'
if os.path.exists(p):
    S = json.load(open(p, encoding='utf-8'))
    print('sessions: %d' % len(S))
    if S:
        print('keys of one session: %s' % list(S[0].keys()))
        for s in S[:3]:
            print('  url=%s' % str(s.get('url'))[:110])
            h = s.get('headers') or s.get('req_headers')
            if h:
                for k, v in (h.items() if isinstance(h, dict) else h):
                    print('    %s: %s' % (k, str(v)[:100]))