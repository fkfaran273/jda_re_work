"""spn_reads2.py — find reads whose VALUES match KB362 dwords / IV dwords
(anywhere in the heap), and histogram their addresses.

    python spn_reads2.py
"""
import json
import os
import struct
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))

imm = json.load(open(os.path.join(WORK, "adj7s4_immruns.json")))["d20a0"]
kb_le = [int(x) for x in imm]
kb_vals = {}
for i, w in enumerate(kb_le):
    kb_vals[w] = ("kb%d_le" % i)
    kb_vals[w ^ 0xCCCCCCCC] = ("kb%d_masked" % i)
    # byte-swapped variants
    b = struct.pack("<I", w)
    kb_vals[struct.unpack(">I", b)[0]] = ("kb%d_be" % i)

blob = bytes.fromhex(open(os.path.join(HERE, "v4_blob.hex")).read().strip())
IV = blob[:16]
iv_vals = set()
for i in range(0, 16, 4):
    w = IV[i:i + 4]
    iv_vals.add(struct.unpack("<I", w)[0])
    iv_vals.add(struct.unpack(">I", w)[0])
    sw = w[::-1]
    iv_vals.add(struct.unpack("<I", sw)[0])
    iv_vals.add(struct.unpack(">I", sw)[0])

hits = []
iv_hits = []
n = 0
with open(os.path.join(HERE, "v4_reads.txt")) as f:
    for ln in f:
        p = ln.split()
        n += 1
        a = int(p[0], 16)
        s = int(p[1])
        v = int(p[2], 16)
        if s == 4 and v in kb_vals:
            hits.append((n, a, v, kb_vals[v]))
        elif s == 4 and v in iv_vals:
            iv_hits.append((n, a, v))
print("total reads", n)
print("KB-value reads:", len(hits))
addr_h = Counter(a for _, a, _, _ in hits)
print("KB-hit addresses:", [(hex(a), c) for a, c in addr_h.most_common(20)])
which = Counter(t for _, _, _, t in hits)
print("which KB:", which.most_common(10))
print("first 30 KB-value reads:")
for e in hits[:30]:
    print("  r%d a=%x v=%08x %s" % e)
print("last 10:", [(e[0], hex(e[1])) for e in hits[-10:]])
print()
print("IV-value reads:", len(iv_hits))
ia = Counter(a for _, a, _ in iv_hits)
print("IV-hit addresses:", [(hex(a), c) for a, c in ia.most_common(16)])
print("first 20 IV reads:", [(e[0], hex(e[1]), "%08x" % e[2]) for e in iv_hits[:20]])
