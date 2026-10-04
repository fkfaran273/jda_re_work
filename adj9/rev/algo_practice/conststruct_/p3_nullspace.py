"""Pass 3: characterize the 22-dim subspace containing all 60 words of KB.

* null space (parity constraints) of the 60x32 GF(2) matrix
* Berlekamp-Massey per bit column -> LFSR order of the word sequence
* AES-256-stride diff table
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_common import *
from collections import defaultdict

W = [int.from_bytes(KB[4*i:4*i+4], "little") for i in range(60)]
Wbe = [int.from_bytes(KB[4*i:4*i+4], "big") for i in range(60)]

# ---- null space of rows: all c in GF(2)^32 with c.w == 0 for every w ----
# build: for each c candidate, check.  2^32 too many -> row-reduce transpose.
# M: rows = words.  We want the orthogonal complement of row-space (dim 22).
# Complement dim 10.  Compute by Gaussian elimination on the words, then
# solve.
def rref(rows, nbits):
    """Return (pivot_lead->row dict) echelon basis."""
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

def nullspace(rows, nbits):
    """Vectors orthogonal to every row (dim = nbits - rank)."""
    basis = rref(rows, nbits)
    leads = set(basis.keys())
    free = [b for b in range(nbits) if b not in leads]
    out = []
    for f in free:
        # vector with 1 at f, and chosen bits at pivot positions so c.basis=0
        v = 1 << f
        for lead, brow in basis.items():
            if (brow >> f) & 1:
                v |= 1 << lead
        out.append(v)
    return out

ns = nullspace(W, 32)
print(f"null space dim = {len(ns)} (expect 32-22=10)")
for v in ns:
    b = v.to_bytes(4, "little")
    print(f"  c=0x{v:08x}  LE bytes {b.hex()}  popcount={bin(v).count('1')}")
# verify
ok = all((v & w).bit_count() % 2 == 0 for v in ns for w in W)
print("all constraints hold on all 60 LE words:", ok)
okbe = all((v & w).bit_count() % 2 == 0 for v in ns for w in Wbe)
print("same constraints on BE words:", okbe)

# per-byte view of the constraints
print("\nconstraint masks per byte (LE word = b0 b1 b2 b3):")
for v in ns:
    print(f"  0x{v:08x} = [{(v>>0)&0xff:02x} {(v>>8)&0xff:02x} {(v>>16)&0xff:02x} {(v>>24)&0xff:02x}]")

# ---- Berlekamp-Massey per bit column (LE word order) ----
def berlekamp_massey(s):
    n = len(s)
    C, B = [1], [1]
    L, m, b = 0, 1, 1
    for i in range(n):
        d = s[i] ^ (sum(C[j] * s[i-j] for j in range(1, L+1)) % 2)
        if d == 1:
            T = C[:]
            need = [0]*m + B
            if len(need) < len(C):
                need += [0]*(len(C)-len(need))
            C = [C[j] ^ (need[j] if j < len(need) else 0) for j in range(max(len(C), len(need)))]
            if L <= i // 2:
                L, m, b = i + 1 - L, 0, 1
        m += 1
    return L

print("\n== Berlekamp-Massey LFSR degree per bit column (LE order, 60 bits) ==")
for bit in range(31, -1, -1):
    seq = [(w >> bit) & 1 for w in W]
    L = berlekamp_massey(seq)
    print(f"  bit{bit:2d}: LFSR deg {L:2d}", end="  ")
    if bit % 8 == 0: print()

# same on bytes: BM over GF(2^8)? skip; instead check linear recurrence over GF(2)
# for the WHOLE 32-bit word: does w[i] = sum c_j w[i-j] hold for small order?
print("\n== whole-word linear recurrence test (w[i] = XOR of earlier words) ==")
# search recurrences of the form w[i] = w[i-a] ^ w[i-b] etc for small taps
for taps in [(1, 8), (4, 8), (1, 2), (2, 8), (1, 4), (8, 12)]:
    good = all(W[i] == W[i-taps[0]] ^ W[i-taps[1]] for i in range(max(taps), 60))
    print(f"  w[i]=w[i-{taps[0]}]^w[i-{taps[1]}]: {good}")

# ---- AES-256 stride diff table (BE words, standard convention) ----
print("\n== d[i] = w[i] ^ w[i-8]  (BE) ==")
for i in range(8, 60):
    d = Wbe[i] ^ Wbe[i-8]
    print(f"  i={i:2d} i%8={i%8} d={d:08x}  d^w[i-1]={d ^ Wbe[i-1]:08x}")
