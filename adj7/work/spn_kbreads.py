"""spn_kbreads.py — KB362 read events in adj7s4_reads.txt: timing, values, PCs.

    python spn_kbreads.py
"""
import json
import os
import struct
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))

KB_LO, KB_HI = 0x900a6ac, 0x900a6ac + 256

imm = json.load(open(os.path.join(WORK, "adj7s4_immruns.json")))["d20a0"]
KB_LE = b"".join(struct.pack("<I", w) for w in imm)
print("KB[0:16] LE bytes:", KB_LE[:16].hex())
print("KB[0:16] masked   :", bytes(b ^ 0xCC for b in KB_LE[:16]).hex())

events = []
n = 0
with open(os.path.join(WORK, "adj7s4_reads.txt")) as f:
    for ln in f:
        p = ln.split()
        if len(p) >= 5:
            n += 1
            a = int(p[2], 16)
            if KB_LO <= a < KB_HI:
                events.append((int(p[0]), int(p[1], 16), a, int(p[3]),
                               int(p[4], 16)))
print("total reads", n, " KB reads", len(events))
for e in events[:80]:
    print("  idx=%d pc=%x a=%x s=%d v=%08x" % e)
print("...")
for e in events[-20:]:
    print("  idx=%d pc=%x a=%x s=%d v=%08x" % e)
idxs = [e[0] for e in events]
print("KB read idx range:", min(idxs), max(idxs))
# gaps
gaps = [(idxs[i + 1] - idxs[i], i) for i in range(len(idxs) - 1)]
big = sorted(gaps, reverse=True)[:20]
print("largest gaps between consecutive KB reads:", big)
pcs = Counter(e[1] for e in events)
print("KB read PCs:", [(hex(pc), c) for pc, c in pcs.most_common(10)])
