"""Pass 1: byte-level statistics, block entropy, trivial relations."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_common import *
from collections import Counter
import math

print("== POPCOUNT ==")
for name, v in (("KB", KB), ("IV2", IV2), ("K", K), ("IV2^K", xor(IV2, K))):
    pc = popcount(v)
    exp = len(v) * 4
    sd = math.sqrt(len(v) * 8 * 0.25)  # binomial sd for bits
    print(f"  {name:5s} len={len(v):3d} ones={pc:4d} expected~{exp} "
          f"z={(pc-exp)/sd:+.2f}")

print("\n== BYTE FREQUENCY (KB, 240 bytes) ==")
c = Counter(KB)
print(f"  distinct={len(c)}/256  max={max(c.values())}  min={min(c.values())} "
      f"entropy={shannon(KB):.4f} (max 8.0)")
print(f"  most common: {c.most_common(6)}")
missing = [x for x in range(256) if x not in c]
print(f"  missing byte values ({len(missing)}): {missing[:30]}{'...' if len(missing)>30 else ''}")

print("\n== BYTE FREQUENCY (IV2+K, 64 bytes) ==")
allk = IV2 + K
c2 = Counter(allk)
print(f"  distinct={len(c2)}/256 entropy={shannon(allk):.4f} top={c2.most_common(5)}")

print("\n== PER-16B-BLOCK ENTROPY OF KB (max 4.0 for 16 bytes) ==")
for i, b in enumerate(blocks(KB)):
    print(f"  B[{i:2d}] {b.hex()}  H={shannon(b):.3f}  distinct={len(set(b)):2d} pc={popcount(b):3d}")
print(f"  K   {K.hex()}  H={shannon(K):.3f}")
print(f"  IV2 {IV2.hex()}  H={shannon(IV2):.3f}")

print("\n== BLOCK XOR TABLE B[i]^B[j] (KB, 15 blocks) -- count zero/low-hamming ==")
B = blocks(KB)
zero_pairs = []
for i in range(15):
    for j in range(i + 1, 15):
        d = xor(B[i], B[j])
        pc = popcount(d)
        if pc <= 16:  # half the 128 bits, p tiny for random
            zero_pairs.append((i, j, pc, d.hex()))
print(f"  pairs with popcount<=16: {len(zero_pairs)}")
for z in zero_pairs:
    print(f"    B[{z[0]}]^B[{z[1]}] pc={z[2]} {z[3]}")

print("\n== BYTE-POSITION MEANS ACROSS 15 BLOCKS (detect per-column bias) ==")
for col in range(16):
    vals = [b[col] for b in B]
    mean = sum(vals) / 15
    print(f"  col{col:2d}: mean={mean:6.1f} (128=neutral) vals={' '.join(f'{v:02x}' for v in vals)}")

print("\n== XOR-DIFF OF CONSECUTIVE BLOCKS B[i]^B[i+1] ==")
for i in range(14):
    print(f"  {i:2d}^{i+1:2d}: {xor(B[i], B[i+1]).hex()}")

print("\n== AUTOCORRELATION of KB bytes at lags 1..120 (Pearson r, |r|>0.25 flagged) ==")
n = len(KB)
m = sum(KB) / n
var = sum((x - m) ** 2 for x in KB) / n
flags = []
for lag in range(1, 120):
    cov = sum((KB[i] - m) * (KB[i + lag] - m) for i in range(n - lag)) / (n - lag)
    r = cov / var
    if abs(r) > 0.25:
        flags.append((lag, round(r, 3)))
print(f"  flagged: {flags if flags else 'none (all |r|<=0.25)'}")

print("\n== BIT-LEVEL: KB as 240x8 bit matrix, rank over GF(2) ==")
def gf2_rank(rows):
    rows = [r for r in rows]
    basis = []
    for r in rows:
        cur = r
        for b in basis:
            cur = min(cur, cur ^ b)
        if cur:
            basis.append(cur)
            basis.sort(reverse=True)
    return len(basis)

rows = []
for i in range(0, 240, 8):
    w = KB[i:i+8]
    rows.append(sum(((w[j] >> (7 - j)) & 1) << (7 - j) for j in range(8)))
# better: treat each byte value as an 8-bit row -> 240 rows of 8 bits
rows = [b for b in KB]
print(f"  rank of 240 bytes as 8-bit rows over GF(2): {gf2_rank(rows)}/8 (8=random full)")
# 15 blocks as 128-bit rows
Brows = [int.from_bytes(b, "big") for b in B]
print(f"  rank of 15 blocks as 128-bit rows over GF(2): {gf2_rank(Brows)}/15")
# 30 half-blocks as 64-bit rows
Hrows = [int.from_bytes(KB[i:i+8], "big") for i in range(0, 240, 8)]
print(f"  rank of 30 8-byte words as 64-bit rows: {gf2_rank(Hrows)}/30")
# K and IV2 as rows
print(f"  IV2 in span of KB blocks (128-bit GF2)? ", end="")
target = int.from_bytes(IV2[:16], "big"); t2 = int.from_bytes(IV2[16:], "big")
print("no quick check below")
print(f"  K rows in span of 15 KB blocks: computing...")
def in_span(target, rows):
    basis = []
    for r in rows:
        cur = r
        for b in basis:
            cur = min(cur, cur ^ b)
        if cur:
            basis.append(cur); basis.sort(reverse=True)
    t = target
    for b in basis:
        t = min(t, t ^ b)
    return t == 0
print(f"    IV2[0:16] in span: {in_span(int.from_bytes(IV2[:16],'big'), Brows)}")
print(f"    IV2[16:32] in span: {in_span(int.from_bytes(IV2[16:],'big'), Brows)}")
print(f"    K[0:16] in span: {in_span(int.from_bytes(K[:16],'big'), Brows)}")
print(f"    K[16:32] in span: {in_span(int.from_bytes(K[16:],'big'), Brows)}")
