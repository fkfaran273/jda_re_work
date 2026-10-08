"""spn_kbwrites.py — locate writes of KB362 / IV dwords in v4_writes.txt,
then the read pattern of those addresses in v4_reads.txt.

    python spn_kbwrites.py
"""
import json
import os
import struct
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))

imm = json.load(open(os.path.join(WORK, "adj7s4_immruns.json")))["d20a0"]
kb_dwords = [int(x) for x in imm]
kb_set = set(kb_dwords)
kb_mask_set = set(w ^ 0xCCCCCCCC for w in kb_dwords)

blob = bytes.fromhex(open(os.path.join(HERE, "v4_blob.hex")).read().strip())
IV = blob[:16]
iv_be = [int.from_bytes(IV[i:i + 4], "big") for i in range(0, 16, 4)]
iv_le = [int.from_bytes(IV[i:i + 4], "little") for i in range(0, 16, 4)]

kb_writes = []      # (widx, addr, value)
iv_writes = []
mask_writes = []
n = 0
with open(os.path.join(HERE, "v4_writes.txt")) as f:
    for ln in f:
        p = ln.split()
        n += 1
        a = int(p[0], 16)
        s = int(p[1])
        v = int(p[2], 16)
        if s != 4:
            continue
        if v in kb_set:
            kb_writes.append((n, a, kb_dwords.index(v)))
        elif v in kb_mask_set:
            mask_writes.append((n, a, kb_dwords.index(v ^ 0xCCCCCCCC)))
        elif v in iv_be:
            iv_writes.append((n, a, "be", iv_be.index(v)))
        elif v in iv_le:
            iv_writes.append((n, a, "le", iv_le.index(v)))
print("total writes", n)
print("KB dword writes:", len(kb_writes))
print("  first 20:", [(e[0], hex(e[1]), "d%d" % e[2]) for e in kb_writes[:20]])
print("  addrs:", Counter(hex(a) for _, a, _ in kb_writes).most_common(10))
print("masked KB writes:", len(mask_writes))
print("  first 10:", [(e[0], hex(e[1]), "d%d" % e[2]) for e in mask_writes[:10]])
print("IV dword writes:", len(iv_writes))
print("  first 20:", [(e[0], hex(e[1]), e[2], "w%d" % e[3]) for e in iv_writes[:20]])
print("  addrs:", Counter(hex(a) for _, a, _, _ in iv_writes).most_common(10))
