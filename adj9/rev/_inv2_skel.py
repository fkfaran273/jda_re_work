"""_inv2_skel.py — complete compact skeleton of the whitening phase."""
import gzip
import json

MAIN = 0x5450001000

A = json.load(gzip.open("_inv2_row7_real.json.gz", "rt"))
wire = A["wire"]
ops = [(e[0], e[1], e[3] + e[4] if e[0] == "E" else e[4], e[5] & 0xFFFFFFFF)
       for e in wire if e[2] == MAIN and e[0] in ("E", "Q")]

# E-only sequence with pc
eseq = [(k, pc, o) for k, (kind, pc, o, v) in enumerate(ops) if kind == "E"]
rb = next(i for i, (k, pc, o) in enumerate(eseq) if pc == 0x119538)

# compact: consecutive E with same pc -> one token (n, pc, abs-range)
toks = []
s = rb
for k in range(rb + 1, len(eseq) + 1):
    if k == len(eseq) or eseq[k][1] != eseq[s][1]:
        pc = eseq[s][1]
        lo = min(eseq[j][2] for j in range(s, k))
        hi = max(eseq[j][2] for j in range(s, k))
        toks.append((k - s, pc, lo, hi))
        s = k
print("E tokens after record build:", len(toks))
# merge consecutive tokens with same pc
merged = []
for (n, pc, lo, hi) in toks:
    if merged and merged[-1][1] == pc:
        merged[-1][0] += n
        merged[-1][2] = min(merged[-1][2], lo)
        merged[-1][3] = max(merged[-1][3], hi)
    else:
        merged.append([n, pc, lo, hi])
print("merged tokens:", len(merged))
for (n, pc, lo, hi) in merged:
    print("  pc=%#x n=%4d abs=[%d..%d]" % (pc, n, lo, hi))
