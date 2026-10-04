"""geom_probe2.py - the claim-layout hypothesis, done properly.

#10 is a separator-less concatenation of claim VALUES in the law's key order
(slice 125 §3).  For our own mint (wh_out.json) we know the map, so we can compute
each claim's value length and its offset inside the concatenation exactly.

Then: does the 56-byte region (#0's W0 + tile, #2, #4's 8 words) encode that layout?
Tested as 32-bit dwords, 16-bit halves, bytes, bitmaps, and simple folds.
"""
import functools
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import desc10_law

h = json.load(open(os.path.join(HERE, "wh_out.json"), encoding="utf-8"))
val = dict((k, v) for k, v in h["mapPairs"])
kind = "session"
keys = desc10_law.desc10_keys(kind, val)
built = desc10_law.build_desc10(val, kind)
if isinstance(built, tuple):
    built = built[0]
if isinstance(built, str):
    built = built.encode("latin1")
print("law keys: %d   build_desc10 len: %d" % (len(keys), len(built)))

lens, offs, o = [], [], 0
for k in keys:
    v = val.get(k)
    s = "" if v is None else str(v)
    lens.append(len(s))
    offs.append(o)
    o += len(s)
total = o
print("key-walk concatenation: %d   (build_desc10: %d)   delta: %d" %
      (total, len(built), len(built) - total))
print("value lengths:", lens)
print("offsets      :", offs)

# --- descriptors from the captured plane (role table, slice 118/122) ---------
S = {}
for st, n, v in h["emits"]:
    S.setdefault(st, {})[n] = v
PL = dict((st, [S[st][k] for k in sorted(S[st])]) for st in S)


def tile_reps(vs):
    best = 0
    for i in range(0, len(vs) - 4):
        t = vs[i:i + 4]
        if not any(t):
            continue
        r = 1
        while i + 4 * (r + 1) <= len(vs) and vs[i + 4 * r:i + 4 * (r + 1)] == t:
            r += 1
        best = max(best, r)
    return best


d0 = max([(tile_reps(vs), vs) for vs in PL.values() if len(vs) == 36],
         key=lambda x: x[0])[1]
d4 = [vs for vs in PL.values() if len(vs) == 8][0]
singles = sorted([vs[0] for vs in PL.values() if len(vs) == 1],
                 key=lambda w: bin(w).count("1"), reverse=True)
d2 = singles[0]
W0, tile = d0[0], d0[1:5]
print()
print("#0  : 36 words, tile reps=%d, W0=%08x tile=%s" %
      (tile_reps(d0), W0, ["%08x" % t for t in tile]))
print("#2  : %08x   (singles in popcount order: %s)" %
      (d2, ["%08x" % w for w in singles]))
print("#4  : %s" % ["%08x" % w for w in d4])

U = [("W0", W0)] + [("tile%d" % k, t) for k, t in enumerate(tile)] + \
    [("#2", d2)] + [("#4[%d]" % k, w) for k, w in enumerate(d4)]

geom = set(lens) | set(offs) | {total, len(keys), sum(lens)}
print()
print("--- membership of geometry numbers in the unknowns ---")
for nm, w in U:
    as32 = w in geom
    h1, h2 = w >> 16, w & 0xFFFF
    as16 = (h1 in geom) or (h2 in geom)
    bts = [(w >> s) & 0xFF for s in (0, 8, 16, 24)]
    as8 = any(b in geom for b in bts)
    print("  %-7s %08x  dword:%-5s half16:%-5s byte:%-5s" % (nm, w, as32, as16, as8))

print()
print("--- folds of lengths/offsets vs #2 and #4[0] ---")
folds = {
    "sum(lens)": sum(lens), "sum(offs)": sum(offs), "xor lens": functools.reduce(lambda a, b: a ^ b, lens, 0),
    "xor offs": functools.reduce(lambda a, b: a ^ b, offs, 0), "max len": max(lens), "max off": max(offs),
    "sum(lens)+sum(offs)": sum(lens) + sum(offs), "n*max": len(keys) * max(lens),
}
for k, v in folds.items():
    print("  %-22s = %-8d  == #2:%s  == #4[0]:%s" % (k, v, v == d2, v == d4[0]))

print()
print("--- do lens/offsets appear as 16-bit fields inside #4 (all pairings)? ---")
pairs = [(d4[i] >> 16, d4[i] & 0xFFFF) for i in range(8)] + \
        [(d4[i] & 0xFFFF, d4[i] >> 16) for i in range(8)]
for idx, (a, b) in enumerate(pairs):
    if a in geom or b in geom:
        print("  #4 word %d halves (%d, %d) -> hit %s" %
              (idx % 8, a, b, "a" if a in geom else "b"))

print()
print("--- per-claim lens as a bitmap / bit positions inside #4 ---")
for nm, w in U:
    bits = [i for i in range(32) if (w >> i) & 1]
    hit = [i for i in bits if i in geom]
    if hit:
        print("  %-7s %08x set-bits=%s geometry-hits=%s" % (nm, w, bits[:16], hit))