import os, re, sys, urllib.parse
from datetime import datetime, timezone
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7ios_pure as sg

RAW = os.path.join(HERE, 'saz_berain', 'raw')
t = open(os.path.join(RAW, '045_c.txt'), encoding='utf-8', errors='replace', newline='').read()
auth = [l.split(': ', 1)[1] for l in t.split('\r\n\r\n', 1)[0].split('\r\n') if l.startswith('Authorization')][0]
sig = re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1).upper()
hdr = bytes.fromhex(sig)[:16].hex().upper()
params = dict(urllib.parse.parse_qsl(t.partition('\r\n\r\n')[2].strip(), keep_blank_values=True))

def sec_of(s):
    m = re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z([+-]\d\d)(\d\d)', s)
    return int(datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp() - int(m.group(2))*3600 - int(m.group(3))*60)

targets = {'sent_at': params['sent_at'], 'created_at': params['created_at'],
           'installed_at': params['installed_at'], 'started_at': params['started_at']}
for name, s in targets.items():
    base = sec_of(s)
    hit = None
    for d in range(-120, 86401):
        if sg.make_header(base + d).hex().upper() == hdr:
            hit = d; break
    print('%-13s base=%d delta=%s' % (name, base, hit))
print('target', hdr)
