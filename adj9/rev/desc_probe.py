# desc_probe.py - offline #2 probe: golden #2 = fb1a8296; try candidate hashes over
# the golden's own desc10 / canonical / H / second / map hashCode / nsign_ts.
import json, struct, zlib, hashlib

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
W = json.load(open(REV + r'\wh4_records.json', encoding='utf-8'))
F = json.load(open(REV + r'\fin_descs.json', encoding='utf-8'))
D = {x['build_idx']: x for x in F['descs']}
T = F['target']
d2 = int(D[2]['data_hex'], 16)
d10 = bytes.fromhex(D[10]['data_hex'])
sec = T['second']
ts = T['nsign_ts']

gi = W.get('golden_sign_input_idx', 7)
si = W['sign_inputs'][gi]
fields = []
for part in si['order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        fields.append((k, v))
val = dict(fields)
# golden H + canonical from the same session (record keys may vary)
Hhex = None
for key in ('h_hex', 'H', 'h'):
    if key in W:
        Hhex = W[key]
        break
if Hhex is None and 'signings' in W:
    Hhex = W['signings'][gi].get('h_hex') or W['signings'][gi].get('H')
canon = W.get('canonicals') or W.get('canonical')
if isinstance(canon, list):
    canon = canon[gi] if len(canon) > gi else canon[0]
print('H =', Hhex)
print('canonical len =', len(canon) if canon else None)
Hb = bytes.fromhex(Hhex) if Hhex else b''

def java_hash(b):
    h = 0
    for c in b:
        h = (h * 31 + c) & 0xFFFFFFFF
    return h

def fnv1a(b):
    h = 0x811C9DC5
    for c in b:
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    return h

def fnv1(b):
    h = 0x811C9DC5
    for c in b:
        h = ((h * 0x01000193) & 0xFFFFFFFF) ^ c
        h &= 0xFFFFFFFF
    return h

def djb2(b):
    h = 5381
    for c in b:
        h = ((h * 33) + c) & 0xFFFFFFFF
    return h

def sdbm(b):
    h = 0
    for c in b:
        h = (c + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h

def digest_words(b):
    out = {}
    for algo in ('md5', 'sha1', 'sha256'):
        d = hashlib.new(algo, b).digest()
        out[algo + '_be0'] = struct.unpack('>I', d[:4])[0]
        out[algo + '_le0'] = struct.unpack('<I', d[:4])[0]
        out[algo + '_beL'] = struct.unpack('>I', d[-4:])[0]
        out[algo + '_leL'] = struct.unpack('<I', d[-4:])[0]
    return out

canon_b = canon.encode('utf-8') if canon else b''
cands = {
    'crc32(d10)': zlib.crc32(d10),
    'crc32(H)': zlib.crc32(Hb),
    'crc32(d10+H)': zlib.crc32(d10 + Hb),
    'crc32(H+d10)': zlib.crc32(Hb + d10),
    'crc32(canon)': zlib.crc32(canon_b),
    'crc32(secBE)': zlib.crc32(struct.pack('>I', sec)),
    'crc32(tsLE8)': zlib.crc32(struct.pack('<Q', ts)),
    'fnv1a(d10)': fnv1a(d10),
    'fnv1(d10)': fnv1(d10),
    'fnv1a(H)': fnv1a(Hb),
    'fnv1a(d10+H)': fnv1a(d10 + Hb),
    'fnv1a(canon)': fnv1a(canon_b),
    'adler(d10)': zlib.adler32(d10),
    'adler(H)': zlib.adler32(Hb),
    'java(d10)': java_hash(d10),
    'java(canon)': java_hash(canon_b),
    'java(H)': java_hash(Hb),
    'djb2(d10)': djb2(d10),
    'sdbm(d10)': sdbm(d10),
    'java(d10)^java(H)': java_hash(d10) ^ java_hash(Hb),
    'crc(d10)^crc(H)': zlib.crc32(d10) ^ zlib.crc32(Hb),
}
# Java Map.hashCode: sum over entries of (hash(key) ^ hash(value)) on UTF-16 chars
mh = 0
for k, v in fields:
    eh = java_hash(k.encode()) ^ java_hash(v.encode())
    mh = (mh + eh) & 0xFFFFFFFF
cands['map.hashCode'] = mh
# header 16B (first 4 dwords of blob) is second-derived; try crc of it
blob = bytes.fromhex(T['blob_hex'])
cands['crc32(blob16)'] = zlib.crc32(blob[:16])
cands['crc32(blob)'] = zlib.crc32(blob)
for algo, d in digest_words(d10).items():
    cands[algo + '(d10)'] = d
for algo, d in digest_words(canon_b).items():
    cands[algo + '(canon)'] = d
for algo, d in digest_words(Hb).items():
    cands[algo + '(H)'] = d

print('golden #2 = %08x' % d2)
hits = [n for n, v in cands.items() if v == d2]
for name, v in cands.items():
    print('  %-24s %08x%s' % (name, v or 0, '  <== MATCH' if v == d2 else ''))
print('HITS:', hits or 'none of %d candidates' % len(cands))
