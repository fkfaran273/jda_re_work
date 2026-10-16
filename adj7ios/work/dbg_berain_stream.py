import os, re, sys, urllib.parse, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7ios_pure as sg

RAW = os.path.join(HERE, 'saz_berain', 'raw')
A31, M31 = sg._A31, sg._M31

def hdr_of(n):
    t = open(os.path.join(RAW, '%03d_c.txt' % n), encoding='utf-8',
             errors='replace', newline='').read()
    a = [l.split(': ', 1)[1] for l in t.split('\r\n\r\n', 1)[0].split('\r\n')
         if l.startswith('Authorization')][0]
    return bytes.fromhex(re.search(r'signature="([0-9A-Fa-f]+)"',
                                   a).group(1))[:16]

rows = {17: 'session', 44: 'event', 45: 'click', 46: 'attr', 75: 'event2'}
hdrs = {n: hdr_of(n) for n in rows}
for n, name in rows.items():
    print('%-8s %s' % (name, hdrs[n].hex().upper()))

# hypothesis: the SDK keeps ONE MINSTD stream seeded at the first request's
# second and each subsequent header is the NEXT 8-draw block in that stream.
sent = 1779250802   # the session/second-seeded second (row 17 delta 0)
x = int(sent) % M31 or 1
found = {}
for step in range(200000):
    d = []
    for _ in range(8):
        x = (A31 * x) % M31
        d.append(x)
    w = [d[2*i] ^ d[2*i+1] for i in range(4)]
    h = b"".join(v.to_bytes(4, 'big') for v in w)
    for n, name in rows.items():
        if h == hdrs[n] and name not in found:
            found[name] = step
            print('%-8s found at stream step %d' % (name, step))
    if len(found) == len(rows):
        break
print('found:', found)
