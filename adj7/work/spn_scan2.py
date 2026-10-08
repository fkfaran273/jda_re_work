"""spn_scan2.py — timeline of body dword writes in adj7s4_stores7.txt.

    python spn_scan2.py
"""
import json
import os
import struct
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))

BLOB = bytes.fromhex(json.load(open(os.path.join(WORK, "adj7s4_out7.json")))
                     ["out_hex"])
BODY = BLOB[16:272]


def swap4(b):
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b) - 3, 4))


stores = []
with open(os.path.join(WORK, "adj7s4_stores7.txt")) as f:
    for ln in f:
        p = ln.split()
        if len(p) >= 5:
            stores.append((int(p[0]), int(p[1], 16), int(p[2], 16),
                           int(p[3]), int(p[4], 16)))
N = len(stores)
print("stores", N)

# body dword -> LE u32
le_vals = [struct.unpack("<I", BODY[4 * i:4 * i + 4])[0] for i in range(64)]
by_val = defaultdict(list)
for i, (idx, pc, a, s, v) in enumerate(stores):
    if s == 4:
        by_val[v].append(i)

print("direct-form body dword write indices (value == LE u32 of wire):")
for d in range(64):
    hits = by_val.get(le_vals[d], [])
    print("  d%02d wire=%08x n=%d %s" % (d, le_vals[d], len(hits),
                                         [h for h in hits[:6]]))

print()
print("swapped-form body dword write indices (value == BE u32 of wire):")
for d in range(64):
    be = int.from_bytes(BODY[4 * d:4 * d + 4], "big")
    hits = by_val.get(be, [])
    print("  d%02d be=%08x n=%d %s" % (d, be, len(hits),
                                       [h for h in hits[:6]]))

# addresses written by the pair PCs, histogram in last part
addrs_51145c = Counter(a for idx, pc, a, s, v in stores if pc == 0x51145c)
print("\n51145c distinct addrs:", len(addrs_51145c),
      "range:", hex(min(addrs_51145c)), hex(max(addrs_51145c)))

# where does 0x9011970 get written over time?
for target in (0x9011970, 0x9011974, 0x9011978, 0x901197c):
    tl = [(i, pc, v) for i, (idx, pc, a, s, v) in enumerate(stores)
          if a == target and s == 4]
    print("\naddr %#x writes: %d" % (target, len(tl)))
    for i, pc, v in tl[:10]:
        print("   i=%d pc=%x v=%08x" % (i, pc, v))
    if len(tl) > 10:
        print("   ...")
        for i, pc, v in tl[-10:]:
            print("   i=%d pc=%x v=%08x" % (i, pc, v))
