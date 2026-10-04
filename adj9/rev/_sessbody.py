import re
from urllib.parse import unquote_plus

d = open(r'D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin', encoding='latin1').read()
m = re.search(r'Content-Length: 1027\r\n\r\n(.*?)HTTP', d, re.S)
if m:
    body = m.group(1)
    parts = [p.split('=', 1) for p in body.split('&') if '=' in p]
    print('=== DEVICE /session BODY (%d params), wire order ===' % len(parts))
    for k, v in parts:
        print('  %-30s %s' % (k, unquote_plus(v)[:70]))
