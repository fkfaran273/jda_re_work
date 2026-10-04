"""chainan.py — structure of the adj9 body whitening matrix.

body(44 dwords) = c  XOR  SUM_i  col_i & P_i     (GF(2), word-parallel)
"""
import json
D = json.load(open("chainchar_row7.json"))
res = D["res"]; N = D["nplain"]; PLAIN = D["plain"]
cW = res["c"]; cB = cW[4:48]
cols = {int(k): res[k] for k in res if k != "c"}
print("constant c (body words 0..43 = blob 4..47):")
for j in range(0, 44, 8):
    print("   ", " ".join("%08x" % x for x in cB[j:j + 8]))
print()
for i in range(N):
    w = cols[i]
    cb = [w[4 + j] ^ cB[j] for j in range(44)]
    nz = [(j, cb[j]) for j in range(44) if cb[j]]
    vals = sorted(set(v for _, v in nz))
    tag = ("UNIFORM %08x" % vals[0]) if len(vals) == 1 else "%d distinct" % len(vals)
    print("P%-2d %-8s nz=%2d %-16s first=%s" % (i, "%s[%d]" % (PLAIN[i][0], PLAIN[i][1]),
          len(nz), tag, " ".join("%d:%08x" % (j, v) for j, v in nz[:4])))
