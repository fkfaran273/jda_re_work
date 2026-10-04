"""nested_probe.py - bit-nesting + bit-position histograms for a[0..7].

Hypothesis from ent_probe pop trend (2.4,4.5,6.6,8.4,10.5,13.1,14.5,16.5):
each successive a-word sets ~2 more random bits. If cumulative, bitsets nest.
Tests over all 11 rows (canon tiles for R/X only where needed):
 1. bits(a[k]) subset of bits(a[k+1])? count per k.
 2. bit-position histogram per slot: which positions ever set (bias?).
 3. R == Xhi ^ Xlo explicit check (11/11?).
 4. pairwise bit-overlap a[k]&a[j] popcounts (shared structure?).
"""
import json, os, sys
from collections import Counter
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
M = 0xFFFFFFFF
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
A = json.load(open(os.path.join(HERE, "app_signings.json"), encoding="utf-8"))[0]
def canon(x):
    raw = bytes.fromhex(x["d0"])
    w = [int.from_bytes(raw[j:j+4], "big") for j in range(0, len(raw), 4)]
    for t in (w[1:5], w[5:9]):
        K13 = (t[3] ^ t[1]) & M
        R = (K13 >> 16) & 0xFFFF
        if (((t[2] ^ t[0]) & M) >> 16) & 0xFFFF == R:
            return w[0], list(t), R
    return w[0], list(w[1:5]), None
def bits(v):
    return set(b for b in range(32) if (v >> b) & 1)
ROWS = []
for i, x in enumerate(S):
    W0, t, R = canon(x)
    a = [int.from_bytes(bytes.fromhex(x["d4"])[j:j+4], "big") for j in range(0, 32, 4)]
    X = (t[0] ^ t[1]) & M
    ROWS.append((i, R, X, a))
W0a, ta, Ra = canon({"d0": A["d0"]})
aa = [int.from_bytes(bytes.fromhex(A["d4"])[j:j+4], "big") for j in range(0, 32, 4)]
ROWS.append(("app", Ra, (ta[0] ^ ta[1]) & M, aa))
print("=== 0. R == Xhi ^ Xlo ? ===")
n = sum(1 for _, R, X, _ in ROWS if R == (((X >> 16) & 0xFFFF) ^ (X & 0xFFFF)))
print("  %d/11" % n)
print("=== 1. nesting bits(a[k]) ⊆ bits(a[k+1]) ===")
for k in range(7):
    n = sum(1 for _, _, _, a in ROWS if bits(a[k]) <= bits(a[k+1]))
    print("  a[%d] ⊆ a[%d]: %d/11" % (k, k+1, n))
print("=== 2. overlap pops a[k]&a[k+1] (mean) ===")
for k in range(7):
    pops = [len(bits(ROWS[r][3][k]) & bits(ROWS[r][3][k+1])) for r in range(len(ROWS))]
    print("  a[%d]&a[%d]: mean %.1f min %d max %d" % (k, k+1, sum(pops)/len(pops), min(pops), max(pops)))
print("=== 3. bit-position histogram per slot (positions set in >=3 rows) ===")
for k in range(8):
    c = Counter()
    for _, _, _, a in ROWS:
        for b in bits(a[k]):
            c[b] += 1
    hot = sorted(b for b, v in c.items() if v >= 3)
    print("  a[%d]: hot=%s nunique=%d" % (k, hot, len(c)))
