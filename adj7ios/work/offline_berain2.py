import os, re, sys, urllib.parse, struct
from datetime import datetime, timezone
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7ios_pure as sg
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

RAW = os.path.join(HERE, 'saz_berain', 'raw')
SDK, HID, NV = 'ios5.5.2', '8', '3.62.0'
A31, M31 = sg._A31, sg._M31
PAT = 'signature="([0-9A-Fa-f]+)"'
ENDPOINTS = {17: 'session', 44: 'event', 45: 'sdk_click',
             46: 'attribution', 75: 'event'}
KIND = {'session': 'session', 'event': 'event', 'sdk_click': 'click',
        'attribution': 'attribution'}

def block(x):
    d = []
    for _ in range(8):
        x = (A31 * x) % M31
        d.append(x)
    w = [d[2*i] ^ d[2*i+1] for i in range(4)]
    return b''.join(v.to_bytes(4, 'big') for v in w), x

def carve(n):
    t = open(os.path.join(RAW, '%03d_c.txt' % n), encoding='utf-8',
             errors='replace', newline='').read()
    head, _, body = t.partition('\r\n\r\n')
    line0 = t.split('\r\n', 1)[0]
    a = [l.split(': ', 1)[1] for l in head.split('\r\n')
         if l.startswith('Authorization')][0]
    if line0.startswith('GET') and '?' in line0:
        q = line0.split(' ', 2)[1].split('?', 1)[1].rsplit(' ', 1)[0]
        params = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
    else:
        params = dict(urllib.parse.parse_qsl(body.strip(),
                                             keep_blank_values=True))
    return params, re.search(PAT, a).group(1).upper()

def sec_of(sent):
    m = re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z([+-]\d\d)(\d\d)',
                 sent)
    if not m:
        return int(datetime.strptime(sent[:19], '%Y-%m-%dT%H:%M:%S')
                   .replace(tzinfo=timezone.utc).timestamp())
    return int(datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S')
               .replace(tzinfo=timezone.utc).timestamp()
               - int(m.group(2)) * 3600 - int(m.group(3)) * 60)

ok = 0
for n, ep in ENDPOINTS.items():
    params, sig = carve(n)
    blob = bytes.fromhex(sig)
    dec = Cipher(algorithms.AES(sg.SEED), modes.CBC(blob[:16])).decryptor()
    rec = dec.update(blob[16:272]) + dec.finalize()
    s = rec.split(b'\x00')[0].decode('latin1')
    ra = re.search(r'"a":\s*"?(\d+)"?', s).group(1)
    rd = re.search(r'"d":\s*"([0-9A-Fa-f]+)"', s).group(1)
    nonce12 = struct.pack('<Q', int(ra.strip())) + bytes.fromhex(rd)
    sec = sec_of(params['sent_at'])
    kind = KIND[ep]
    hit = None
    # the seed is the signing second; within the same second each further
    # sign ADVANCES the stream (no reseed) -- step 0/1/2 ...
    for dsec in range(-300, 301):
        x = int(sec + dsec) % M31 or 1
        for step in range(3):
            h, x = block(x)
            if h == blob[:16]:
                hit = (dsec, step)
                break
        if hit:
            break
    # full blob compare at the found (dsec, step): re-seed at that second and
    # advance `step` blocks, then mint the body with the SAME 16 bytes.
    whole = None
    if hit:
        dsec, step = hit
        x = int(sec + dsec) % M31 or 1
        h = None
        for _ in range(step + 1):
            h, x = block(x)
        claims = sg.build_claims(kind, params, client_sdk=SDK,
                                 include_block2=True)
        # cert40: read it back out of the genuine record (ASCII zeros here)
        rc = re.search(r'"c":\s*"([0-9A-Fa-f]*)"', s).group(1)
        cert40 = bytes.fromhex(rc) if rc else None
        H = sg.commitment_digest(claims, nonce12)
        record = sg.build_record(H, nonce12)
        body = sg.cbc_encrypt(record, h)
        mine = h + body + __import__('hmac').new(sg.DK37, body,
                                                 __import__('hashlib').sha256).digest()
        whole = (mine.hex().upper() == sig)
    print('  row %-3d %-11s kind=%-11s dsec=%-4s step=%s  WHOLE=%s'
          % (n, ep, kind, hit[0] if hit else None, hit[1] if hit else None,
             whole))
    if whole:
        ok += 1
print('byte-exact: %d/%d' % (ok, len(ENDPOINTS)))
