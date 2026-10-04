"""Pass 2: exploit the rank deficiency of KB's 60 32-bit words.

If the key schedule is AFFINE over GF(2) (S-box replaced by a linear map),
every word is an affine combination of the 8 master words + rcon words,
so the rank cannot exceed 8 + (#independent rcon words).  Rank 22 fits.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_common import *

def gf2_rank_and_basis(rows):
    basis = {}
    for r in rows:
        cur = r
        while cur:
            lead = cur.bit_length() - 1
            if lead in basis:
                cur ^= basis[lead]
            else:
                basis[lead] = cur
                break
    return basis

# words, both endiannesses
W_be = [int.from_bytes(KB[4*i:4*i+4], "big") for i in range(60)]
W_le = [int.from_bytes(KB[4*i:4*i+4], "little") for i in range(60)]

for nm, W in (("big-endian words", W_be), ("little-endian words", W_le)):
    basis = gf2_rank_and_basis(W)
    leads = sorted(basis.keys(), reverse=True)
    missing = [b for b in range(32) if b not in basis]
    print(f"{nm}: rank={len(basis)}/32")
    print(f"  leading bits present: {leads}")
    print(f"  bit positions NEVER a leading bit (untouched anchor dims): {missing}")

# 64-bit pairing
W8 = [int.from_bytes(KB[8*i:8*i+8], "big") for i in range(30)]
b8 = gf2_rank_and_basis(W8)
print(f"8-byte words: rank={len(b8)}/64, leading bits: {sorted(b8.keys(), reverse=True)}")

# find explicit low-weight dependencies among the 60 BE words:
# solve x^T M = 0 -> null space of M^T (60 cols, rank 22 -> dim 38)
# find small-weight null vectors via meet-in-the-middle on subsets? Simplest:
# look for XOR relations w[i]^w[j]^w[k] == 0 and w[i]^w[j] == w[k]^w[l]
vals = {}
trip = []
for i in range(60):
    for j in range(i+1, 60):
        v = W_be[i] ^ W_be[j]
        vals.setdefault(v, []).append((i, j))
# pairs XOR to zero?
print("\npairs of words XOR to zero:", [v for v in vals if v == 0])
# triples: w[i]^w[j] == w[k]
pairmap = {W_be[i]: i for i in range(60)}
found = []
for (i, j), vlist in vals.items():
    if vlist and vlist[0][0] == i:
        if v in pairmap:
            k = pairmap[v]
            if k not in (i, j):
                found.append((i, j, k))
print(f"word triples w[i]^w[j]==w[k]: {found[:20]} (total {len(found)})")

# 4-term relations via meet in middle on pair-XOR values
from collections import defaultdict
pairxor = defaultdict(list)
for i in range(60):
    for j in range(i+1, 60):
        pairxor[W_be[i] ^ W_be[j]].append((i, j))
rel4 = []
for v, ps in pairxor.items():
    if len(ps) >= 2 and v != 0:
        for a in range(len(ps)):
            for b in range(a+1, len(ps)):
                (i, j), (k, l) = ps[a], ps[b]
                if len({i, j, k, l}) == 4:
                    rel4.append((i, j, k, l))
print(f"4-word relations w[i]^w[j]^w[k]^w[l]==0: {len(rel4)}")
for r in rel4[:40]:
    i, j, k, l = r
    print(f"   w[{i}]^w[{j}] == w[{k}]^w[{l}]   "
          f"(i%8={i%8},{j%8},{k%8},{l%8})")

# the schedule-hypothesis diffs: d[i] = w[i] ^ w[i-8], i=8..59
print("\n== AES-256-stride diffs d[i] = w[i]^w[i-8] ==")
for i in range(8, 60):
    d = W_be[i] ^ W_be[i-8]
    e = d ^ W_be[i-1]
    print(f"  i={i:2d} i%8={i%8} d={d:08x}  d^w[i-1]={e:08x}")
