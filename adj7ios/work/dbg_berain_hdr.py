import os, re, sys, urllib.parse
from datetime import datetime, timezone
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7ios_pure as sg

RAW = os.path.join(HERE, 'saz_berain', 'raw')
t = open(os.path.join(RAW, '045_c.txt'), encoding='utf-8', errors='replace', newline='').read()
head, _, body = t.partition('\r\n\r\n')
auth = [l.split(': ', 1)[1] for l in head.split('\r\n') if l.startswith('Authorization')][0]
sig = re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1).upper()
blob = bytes.fromhex(sig)
hdr = blob[:16].hex().upper()
sent = dict(urllib.parse.parse_qsl(body.strip(), keep_blank_values=True))['sent_at']
m = re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z([+-]\d\d)(\d\d)', sent)
base = int(datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp() - int(m.group(2))*3600 - int(m.group(3))*60)
print('target header:', hdr)
hit = None
for d in range(-30000, 30001):
    if sg.make_header(base + d).hex().upper() == hdr:
        hit = d; break
print('header delta (wide +-30000):', hit)
if hit is not None:
    print('   =', base + hit, 'vs sent second', base)
