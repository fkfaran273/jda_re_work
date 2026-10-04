"""_inv2_pass.py v2 — aggregated pass structure + region-dependence diff."""
import gzip
import json
from collections import Counter

MAIN = 0x5450001000

A = json.load(gzip.open("_inv2_row7_real.json.gz", "rt"))
B = json.load(gzip.open("_inv2_row7_rand.json.gz", "rt"))

evA = [e for e in A["wire"] if e[0] == "E" and e[2] == MAIN]
evB = [e for e in B["wire"] if e[0] == "E" and e[2] == MAIN]
seqA = [(e[1], e[3] + e[4]) for e in evA]
seqB = [(e[1], e[3] + e[4]) for e in evB]
print("schedule identical:", seqA == seqB)

# runs: consecutive E events with the same pc (Q/PUSH/POP may interleave)
runs = []
s = 0
for k in range(1, len(evA) + 1):
    if k == len(evA) or evA[k][1] != evA[s][1]:
        runs.append((s, k, evA[s][1]))
        s = k

# merge runs separated only by small gaps of other-pc noise?  No — instead
# aggregate GLOBALLY by pc and print the chronological phase list.
chron = []
for (s, e, pc) in runs:
    lo = min(evA[k][3] + evA[k][4] for k in range(s, e))
    hi = max(evA[k][3] + evA[k][4] for k in range(s, e))
    d = sum(1 for k in range(s, e) if evA[k][5] != evB[k][5])
    chron.append((s, e, pc, e - s, d, lo, hi))

print("\nchronological pc phases (n>=8 only):")
for (s, e, pc, n, d, lo, hi) in chron:
    if n >= 8:
        print("  ev%6d pc=%#x n=%5d diff=%5d abs=[%d..%d]" % (s, pc, n, d, lo, hi))

print("\nglobal per-pc aggregation (n>=16):")
agg = defaultdict(lambda: [0, 0, 1 << 30, -1])
for (s, e, pc, n, d, lo, hi) in chron:
    a = agg[pc]
    a[0] += n
    a[1] += d
    a[2] = min(a[2], lo)
    a[3] = max(a[3], hi)
for pc, (n, d, lo, hi) in sorted(agg.items(), key=lambda kv: -kv[1][0]):
    if n >= 16:
        print("  pc=%#x tot=%5d diff=%5d abs=[%d..%d]" % (pc, n, d, lo, hi))
