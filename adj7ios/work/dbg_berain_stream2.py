import os, re, sys, urllib.parse
from datetime import datetime, timezone
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7ios_pure as sg
A31, M31 = sg._A31, sg._M31
RAW = os.path.join(HERE, 'saz_berain', 'raw')
PAT = 'signature="([0-9A-Fa-f]+)"'

def parts(n):
    t = open(os.path.join(RAW, '%03d_c.txt' % n), encoding='utf-8',
             errors='replace', newline='').read()
    a = [l.split(': ', 1)[1] for l in t.split('\r\n\r\n', 1)[0].split('\r\n')
         if l.startswith('Authorization')][0]
    blob = bytes.fromhex(re.search(PAT, a).group(1))
    return blob[:16], t.partition('\r\n\r\n')[2].strip()

def block(x):
    d = []
    for _ in range(8):
        x = (A31 * x) % M31
        d.append(x)
    w = [d[2*i] ^ d[2*i+1] for i in range(4)]
    return b"".join(v.to_bytes(4, 'big') for v in w), x

for n, name in ((17, 'session'), (44, 'event'), (45, 'click'), (46, 'attr'),
                (75, 'event2')):
    hdr, body = parts(n)
    p = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
    sent = p['sent_at']
    m = re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z([+-]\d\d)(\d\d)',
                 sent)
    sec = int(datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S')
              .replace(tzinfo=timezone.utc).timestamp()
              - int(m.group(2)) * 3600 - int(m.group(3)) * 60)
    x = int(sec) % M31 or 1
    hits = []
    for step in range(4):
        h, x = block(x)
        if h == hdr:
            hits.append(step)
    print('%-8s sec=%d header==stream step(s) %s  (sent %s)'
          % (name, sec, hits, sent))
