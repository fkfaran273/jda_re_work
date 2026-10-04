"""Pass 3b: correct RREF nullspace + Berlekamp-Massey."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_common import *

W = [int.from_bytes(KB[4*i:4*i+4], "little") for i in range(60)]
Wbe = [int.from_bytes(KB[4*i:4*i+4], "big") for i in range(60)]

def rref(rows, nbits):
    """Full reduced row echelon basis: dict lead->row, each pivot in 1 row."""
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
    # back-substitute: clear pivot bits from OTHER rows
    leads = sorted(basis.keys())
    for lead in leads:
        for other in leads:
            if other != lead and (basis[other] >> lead) & 1:
                basis[other] ^= basis[lead]
    return basis

def nullspace(rows, nbits):
    basis = rref(rows, nbits)
    leads = set(basis.keys())
    free = [b for b in range(nbits) if b not in leads]
    out = []
    for f in free:
        v = 1 << f
        for lead, brow in basis.items():
            if (brow >> f) & 1:
                v |= 1 << lead
        out.append(v)
    return out

for nm, words, nbits in (("LE 32-bit", W, 32), ("BE 32-bit", Wbe, 32)):
    ns = nullspace(words, nbits)
    ok = all((v & w).bit_count() % 2 == 0 for v in ns for w in words)
    print(f"{nm}: {len(ns)} constraints, all hold: {ok}")
    for v in ns:
        b = v.to_bytes(4, "little" if "LE" in nm else "big")
        print(f"  c=0x{v:08x} bytes={b.hex()} pc={bin(v).count('1')}")

# Berlekamp-Massey, GF(2)
def bm(s):
    n = len(s)
    C, B = [1], [1]          # polynomials, index = degree
    L = 0; m = 1
    for i in range(n):
        d = s[i]
        for j in range(1, L + 1):
            if j < len(C):
                d ^= C[j] & s[i - j]
        if d:
            if 2 * L <= i:
                T = C[:]
                # C ^= x^m * B
                shifted = [0] * m + B
                if len(shifted) < len(C):
                    shifted += [0] * (len(C) - len(shifted))
                C = list(C) + [0] * (len(shifted) - len(C)) if len(C) < len(shifted) else C
                for j in range(len(shifted)):
                    C[j] ^= shifted[j]
                B = T
                L = i + 1 - L
                m = 1
            else:
                shifted = [0] * m + B
                if len(C) < len(shifted):
                    C = C + [0] * (len(shifted) - len(C))
                for j in range(len(shifted)):
                    C[j] ^= shifted[j]
                m += 1
    return L

# sanity
import random
random.seed(2)
print("\nBM sanity: random 60 bits ->", max(bm([random.getrandbits(1) for _ in range(60)]) for _ in range(20)), "(expect ~30)")
print("BM sanity: LFSR deg-8 sequence ->", bm([(1 if i < 8 else 0) for i in range(60)]), "(expect small)")

print("\n== BM per bit column, LE word order ==")
res = {}
for bit in range(32):
    seq = [(w >> bit) & 1 for w in W]
    res[bit] = bm(seq)
for bit in sorted(res, reverse=True):
    print(f"  bit{bit:2d}: deg {res[bit]:2d}")

print("\n== BM per bit column, BE word order ==")
resb = {}
for bit in range(32):
    seq = [(w >> bit) & 1 for w in Wbe]
    resb[bit] = bm(seq)
for bit in sorted(resb, reverse=True):
    print(f"  bit{bit:2d}: deg {resb[bit]:2d}")
