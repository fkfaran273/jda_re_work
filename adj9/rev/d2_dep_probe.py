"""d2_dep_probe.py - map how descriptor #2 (d2, 1 word) propagates into the
FinEx blob body (words 4-47), and cross-check d4[0]/d4[4].

Base: corpus row 7 (all_signings.json row 7 + pair_h3.json i=7 signing second
1789240512).  The base run MUST reproduce the captured blob (validation).

Probes (each a full FinEx run):
  d2: base, ^0x1, ^0x2, ^0x80000000, +1, 0, 0xFFFFFFFF
  d4[0]: ^0x1, ^0x80000000, ^0x00010000
  d4[4]: ^0x1, ^0x80000000, ^0x00010000

For each: which of the 48 words moved, XOR delta and ADD delta per word.
Row 7's d2 = 0xfb1a8296 has bit0 == 0, so the ^1 probe and the +1 probe must
produce IDENTICAL blobs (internal consistency check of the harness).
"""
import json
import struct
import sys
import time

sys.path.insert(0, '.')
import mint_pipeline as M

OUT_JSON = 'd2_probe_result.json'

rows = json.load(open('all_signings.json', encoding='utf-8'))
pairs = {r['i']: r for r in json.load(open('pair_h3.json', encoding='utf-8'))}
r = rows[7]
sec = pairs[7]['second']
cap = bytes.fromhex(pairs[7]['blob'])

d0w = list(struct.unpack('>36I', bytes.fromhex(r['d0'])))
d2w = struct.unpack('>I', bytes.fromhex(r['d2']))[0]
d4w = list(struct.unpack('>8I', bytes.fromhex(r['d4'])))
claims = bytes.fromhex(r['d10'])
unp = len(claims)
pad = (-unp) % 4
padded = claims + b'\x00' * pad
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")


def mk(d0, d2, d4):
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
          2: (1, 0, d2), 7: (1, 0, struct.pack(">I", unp)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
          1: (0, 0, b""), 3: (0, 0, b"")}
    return [by[i] for i in M.VA_ORDER]


def run(d0w_, d2w_, d4w_):
    d0 = b''.join(struct.pack('>I', w & 0xFFFFFFFF) for w in d0w_)
    d2 = struct.pack('>I', d2w_ & 0xFFFFFFFF)
    d4 = b''.join(struct.pack('>I', w & 0xFFFFFFFF) for w in d4w_)
    return M.finex_mint(mk(d0, d2, d4), sec)[0]


def diff48(b):
    """(idx, xor_delta, add_delta) vs the base blob words."""
    ww = struct.unpack('>48I', b)
    return [(i, ww[i] ^ bw[i], (ww[i] - bw[i]) & 0xFFFFFFFF)
            for i in range(48) if ww[i] != bw[i]]


out = {'row': 7, 'second': sec, 'base_d2': '%08x' % d2w,
       'base_d4': ['%08x' % w for w in d4w], 'probes': []}

t0 = time.time()
base = run(d0w, d2w, d4w)
bw = struct.unpack('>48I', base)
out['base_matches_capture'] = (base.hex() == cap.hex())
out['base'] = base.hex()
print("[probe] base (%.0f s) matches_capture=%s"
      % (time.time() - t0, out['base_matches_capture']), flush=True)
json.dump(out, open(OUT_JSON, 'w'), indent=1)

PROBES = [
    ('d2_xor1', 'd2', d2w ^ 0x00000001),
    ('d2_xor2', 'd2', d2w ^ 0x00000002),
    ('d2_xor80000000', 'd2', d2w ^ 0x80000000),
    ('d2_plus1', 'd2', (d2w + 1) & 0xFFFFFFFF),
    ('d2_zero', 'd2', 0),
    ('d2_ffffffff', 'd2', 0xFFFFFFFF),
    ('d4_0_xor1', 'd4_0', d4w[0] ^ 0x00000001),
    ('d4_0_xor80000000', 'd4_0', d4w[0] ^ 0x80000000),
    ('d4_0_xor00010000', 'd4_0', d4w[0] ^ 0x00010000),
    ('d4_4_xor1', 'd4_4', d4w[4] ^ 0x00000001),
    ('d4_4_xor80000000', 'd4_4', d4w[4] ^ 0x80000000),
    ('d4_4_xor00010000', 'd4_4', d4w[4] ^ 0x00010000),
]

for name, which, newval in PROBES:
    t = time.time()
    if which == 'd2':
        b = run(d0w, newval, d4w)
    elif which.startswith('d4_'):
        k = int(which.split('_')[1])
        d4n = d4w[:k] + [newval] + d4w[k + 1:]
        b = run(d0w, d2w, d4n)
    ww = struct.unpack('>48I', b)
    moved = diff48(b)
    entry = {'probe': name, 'which': which,
             'new_val': '%08x' % (newval & 0xFFFFFFFF),
             'blob': b.hex(), 'sec_diff': time.time() - t,
             'n_moved': len(moved),
             'moved': [(i, '%08x' % x, '%08x' % y) for i, x, y in moved]}
    out['probes'].append(entry)
    json.dump(out, open(OUT_JSON, 'w'), indent=1)
    print("[probe] %-18s new=%08x moved=%2d words=%s..%s (%.0f s)"
          % (name, newval & 0xFFFFFFFF, len(moved),
             [i for i, _, _ in moved][:8], [i for i, _, _ in moved][-3:],
             time.time() - t), flush=True)

# consistency: ^1 vs +1 (base bit0 == 0 -> identical blobs expected)
p1 = next(p for p in out['probes'] if p['probe'] == 'd2_xor1')
pp = next(p for p in out['probes'] if p['probe'] == 'd2_plus1')
out['xor1_equals_plus1'] = (p1['blob'] == pp['blob'])
json.dump(out, open(OUT_JSON, 'w'), indent=1)
print("[check] d2 ^1 blob == d2 +1 blob: %s (base bit0=0 -> must be True)"
      % out['xor1_equals_plus1'], flush=True)
print("saved", OUT_JSON, flush=True)
