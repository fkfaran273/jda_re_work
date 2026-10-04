"""dep_probe.py - per-region-word dependency probes for the body decoder.

For each probe: run FinEx on row 7's descriptors with ONE region word replaced
by word^0xFFFFFFFF, diff the 48 blob words vs the real-region run, and record
the per-word delta semantics (xor/add/other) — the fingerprint of the mixing op.
"""
import json
import struct
import sys
import time

sys.path.insert(0, '.')
import mint_pipeline as M

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


def run(d0w, d2w, d4w):
    d0 = b''.join(struct.pack('>I', w & 0xFFFFFFFF) for w in d0w)
    d2 = struct.pack('>I', d2w & 0xFFFFFFFF)
    d4 = b''.join(struct.pack('>I', w & 0xFFFFFFFF) for w in d4w)
    return M.finex_mint(mk(d0, d2, d4), sec)[0]


out = {}
t0 = time.time()
base = run(d0w, d2w, d4w)
out['base_matches_capture'] = base.hex() == cap.hex()
out['base'] = base.hex()
print("[probe] base done (%.0f s) matches_capture=%s"
      % (time.time() - t0, out['base_matches_capture']), flush=True)
bw = struct.unpack('>48I', base)

probes = [('d2', 0, d2w ^ 0xFFFFFFFF)]
for i in range(8):
    probes.append(('d4_%d' % i, i, d4w[i] ^ 0xFFFFFFFF))
for i in (0, 1, 2, 3):   # W0, X, T0, T1 first; extend after inspection
    probes.append(('d0_%d' % i, 100 + i, d0w[i] ^ 0xFFFFFFFF))

results = []
for name, which, newval in probes:
    t = time.time()
    if name == 'd2':
        b = run(d0w, newval, d4w)
    elif name.startswith('d4'):
        b = run(d0w, d2w, d4w[:which] + [newval] + d4w[which + 1:])
    else:
        di = which - 100
        b = run(d0w[:di] + [newval] + d0w[di + 1:], d2w, d4w)
    ww = struct.unpack('>48I', b)
    moved = [(i, ww[i] ^ bw[i], (ww[i] - bw[i]) & 0xFFFFFFFF) for i in range(48) if ww[i] != bw[i]]
    entry = {'probe': name, 'sec_diff': time.time() - t,
             'moved': [(i, '%08x' % x, '%08x' % y) for i, x, y in moved]}
    results.append(entry)
    print("[probe] %-8s moved=%2d  words=%s  (%.0f s)"
          % (name, len(moved), [i for i, _, _ in moved][:12], time.time() - t), flush=True)

out['probes'] = results
json.dump(out, open('dep_probe_result.json', 'w'), indent=1)
print("saved dep_probe_result.json", flush=True)
