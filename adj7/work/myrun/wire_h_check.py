import os, sys, re, urllib.parse
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7_pure as A

def load(folder, n):
    p = os.path.join(HERE, folder, '%02d_c.txt' % n)
    t = open(p, encoding='utf-8', errors='replace', newline='').read()
    head, _, body = t.partition('\r\n\r\n')
    line0 = t.split('\r\n', 1)[0]
    if line0.startswith('GET') and '?' in line0:
        qs = line0.split(' ', 2)[1].split('?', 1)[1].rsplit(' ', 1)[0]
        return head, qs.strip()
    return head, body.strip()

def wire_consistency(folder, n, kind):
    head, body = load(folder, n)
    wire_map = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
    m = re.search(r'signature="([0-9A-F]+)"', head)
    blob = bytes.fromhex(m.group(1))
    # decrypt record with SEED, IV=header
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    dec = Cipher(algorithms.AES(A.SEED), modes.CBC(blob[:16])).decryptor()
    rec = dec.update(blob[16:272]) + dec.finalize()
    s = rec.split(b'\x00')[0].decode('latin1')
    import json
    # record is JSON-ish: {"a": ..., "b": "H", "c": "cert", "d": "nonce8", "e": ...}
    rh = re.search(r'"b":\s*"([0-9A-Fa-f]+)"', s).group(1).upper()
    rc = re.search(r'"c":\s*"([0-9A-Fa-f]+)"', s).group(1).upper()
    # nonce12 = u64le(a) + unhex(d)
    ra = re.search(r'"a":\s*"?(\d+)"?', s).group(1)
    rd = re.search(r'"d":\s*"([0-9A-Fa-f]+)"', s).group(1)
    import struct
    a_int = int(ra.strip())
    nonce12 = struct.pack('<Q', a_int) + bytes.fromhex(rd)
    # rebuild claims from WIRE-parsed map (server's view) + block2
    claims = A.build_claims(kind, dict(wire_map, activity_kind=kind, client_sdk='android5.6.0'), include_block2=True)
    h = A.commitment_digest(claims, nonce12, rc.encode()).hex().upper()
    print('%s/%02d %-11s wireH_match=%s (claims %dB)' % (folder, n, kind, h == rh, len(claims)))

for folder, n, kind in [('saz_live/raw',6,'session'),('saz_live/raw',8,'click'),('saz_live/raw',10,'attribution'),('saz_live/raw',26,'event'),('saz_new/raw',65,'session'),('saz_new/raw',66,'click'),('saz_new/raw',67,'attribution'),('saz_new/raw',68,'attribution'),('saz_new/raw',69,'event')]:
    wire_consistency(folder, n, kind)
