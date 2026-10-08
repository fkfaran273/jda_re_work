"""spn_reads1.py — mine v4_reads.txt: KB-region reads, IV reads, their
values and order during the chunk phase.

    python spn_reads1.py
"""
import os
import struct
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
KB_LO, KB_HI = 0x900a6a8, 0x900a6a8 + 256

blob = bytes.fromhex(open(os.path.join(HERE, "v4_blob.hex")).read().strip())
IV = blob[:16]
body = blob[16:272]


def swap4(b):
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b) - 3, 4))


kb_events = []
iv_events = []
n = 0
with open(os.path.join(HERE, "v4_reads.txt")) as f:
    for ln in f:
        p = ln.split()
        n += 1
        a = int(p[0], 16)
        s = int(p[1])
        v = int(p[2], 16)
        if KB_LO <= a < KB_HI:
            kb_events.append((n, a, s, v))
        elif v in (int.from_bytes(IV[0:4], 'little'),
                   int.from_bytes(IV[0:4], 'big'),
                   int.from_bytes(swap4(IV)[0:4], 'little'),
                   int.from_bytes(swap4(IV)[0:4], 'big')) and s == 4:
            iv_events.append((n, a, s, v))
print("total reads", n)
print("KB reads", len(kb_events))
print("IV-dword-value reads", len(iv_events))
print("first KB reads:")
for e in kb_events[:24]:
    print("  r%d a=%x s=%d v=%08x" % e)
print("last KB reads:")
for e in kb_events[-12:]:
    print("  r%d a=%x s=%d v=%08x" % e)
idxs = [e[0] for e in kb_events]
gaps = sorted([((idxs[i + 1] - idxs[i]), i) for i in range(len(idxs) - 1)],
              reverse=True)[:16]
print("largest KB-read gaps:", gaps)
addrs = Counter(e[1] for e in kb_events)
print("KB addr histogram (first 8):", [(hex(a), c) for a, c in
                                        sorted(addrs.items())[:8]])
print("KB read count per addr: min %d max %d" % (min(addrs.values()),
                                                 max(addrs.values())))
# distinct values seen per address
vals = {}
for _, a, _, v in kb_events:
    vals.setdefault(a, set()).add(v)
multi = {hex(a): len(s) for a, s in vals.items() if len(s) > 1}
print("addrs with >1 distinct value:", multi)
