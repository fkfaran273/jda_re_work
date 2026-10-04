# tap_check.py - read the device's own /attribution traffic from the wire tap
import os
import re
import time

P = r'D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin'
AUID = '6ce5b958'   # this install's android_uuid prefix
GAID = 'e7262a88'   # the clicked GAID

if not os.path.exists(P):
    print('no dump file:', P)
    raise SystemExit(1)
mt = time.strftime('%H:%M:%S', time.localtime(os.path.getmtime(P)))
print('dump mtime %s (%.1f min ago), size %d'
      % (mt, (time.time() - os.path.getmtime(P)) / 60, os.path.getsize(P)))
raw = open(P, 'rb').read()
for tag, pat in (('auid', AUID.encode()), ('gaid', GAID.encode())):
    hits = [m.start() for m in re.finditer(re.escape(pat), raw)]
    print('%s hits: %d %s' % (tag, len(hits), hits[:6]))
    for h in hits[-2:]:
        seg = raw[max(0, h - 500):h + 900]
        print('--- @%d ---' % h)
        print(seg.decode('latin1', 'replace').replace('\r', ''))
