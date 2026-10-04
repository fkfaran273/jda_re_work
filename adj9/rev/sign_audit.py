# sign_audit.py - offline signature audit over all 10 device captures.
# Answers:
#   Q1 do #0/#2/#4 vary per-signing or per-second?  (structure)
#   Q2 does #4 encode a digest/HMAC of its inputs?  (auth binding)
#   Q3 does our Python mint (#4 computed from Random3/H) match ANY capture?
#   Q4 are #0/#2 derivable from second/sec + a captured signing input?
import json, struct, hashlib, zlib, sys, os
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev')
import header_gen as hg
HERE = os.path.dirname(os.path.abspath(__file__))
R = json.load(open(os.path.join(HERE, 'all_signings.json'), encoding='utf-8'))

def d(name, b):
    return int.from_bytes(bytes.fromhex(b), 'big') if b else 0
def chunks(b, n=4):
    return [b[i:i+n] for i in range(0, len(b), n)]

print('=== 10 device signings ===')
rows = []
for i, s in enumerate(R):
    b0 = bytes.fromhex(s['d0'])
    # d0 prefix (first 8 B) + recurring tile
    pre = b0[:8].hex()
    tile = b0[8:20].hex() if len(b0) >= 20 else b0[8:16].hex()
    tiles = chunks(b0[8:])
    tile_set = sorted({t.hex() for t in tiles})
    rows.append({
        'i': i, 'src': s['src'], 'ev': s.get('ev', 0),
        'sec_hex': s['d2'], 'sec_val': d('d2', s['d2']),
        'd4': s['d4'], 'd4B': bytes.fromhex(s['d4']),
        'd0pre': pre, 'd0tile': tile, 'ntiles': len(tile_set),
        'd7': s.get('d7'),
    })
    print(f"#{i} {s['src'][12:]:>6} ev={s.get('ev','?'):>6} "
          f"sec={s['d2']} d0pre={pre} tile={tile_set[0] if len(tile_set)==1 else '?'} "
          f"ntiles={len(tile_set)} d4={s['d4'][:16]}")

print('\n=== Q1: per-signing vs per-second ===')
sec_groups = {}
for r in rows:
    sec_groups.setdefault(r['sec_val'], []).append(r['i'])
print('sec -> indices:', {sec: idx for sec, idx in sec_groups.items()})
# signings sharing a sec must share d0/d4 if deterministic
for sec, idxs in sec_groups.items():
    if len(idxs) > 1:
        same0 = all(R[a]['d0'] == R[b]['d0'] for a in idxs for b in idxs)
        same4 = all(R[a]['d4'] == R[b]['d4'] for a in idxs for b in idxs)
        print(f'  sec {sec:#010x}: {len(idxs)} signings, d0 identical={same0}, d4 identical={same4}')

print('\n=== Q2: is #4 a digest of any input? ===')
TARGET = bytes.fromhex(R[6]['d4'])  # golden
d10 = bytes.fromhex(R[6]['d10'])
print(f'golden #4 head: {TARGET[:8].hex()}  tail: {TARGET[-8:].hex()}')
# candidate inputs (golden signing context)
W = json.load(open(os.path.join(HERE, 'wh4_records.json'), encoding='utf-8'))
si = W['sign_inputs'][W['golden_sign_input_idx']]
order = si['order']
Hhex = W.get('header_law_16') or None
print('candidate inputs to test against #4:')
cands = {'d10': d10, 'd10+H8': d10 + bytes.fromhex('202fa2e575ee0f9f2f9aea68150e')[:8]}
for name, inp in cands.items():
    for algo in ('md5','sha1','sha256','sha384','sha512'):
        dg = hashlib.new(algo).digest(inp)
        if TARGET[:len(dg)] == dg[:len(TARGET)] or TARGET == dg[:len(TARGET)]:
            print(f'  HIT {name} {algo} prefix')
    for k in (zlib.crc32, zlib.adler32):
        v = k(inp) & 0xffffffff
        if v == d('sec', R[6]['d2']) or True:
            pass
# byte-position correlation: for each #4 byte, which d10-offset range differs?
print('byte-level: #4 bytes 9..31 are opaque tail; head bytes 0..8 packed flags.')
print('  bit analysis (set/clear counts across 10 signings):')
import collections
bits = collections.Counter()
for r in rows:
    for byte_i in range(len(r['d4B'])):
        for bit_i in range(8):
            if (r['d4B'][byte_i] >> bit_i) & 1:
                bits[(byte_i, bit_i)] += 1
n = len(rows)
print('  bytes 0-3 set-rate: ', [f'{bits[(b,bi)]/n:.1f}' for b in range(4) for bi in range(8)])
