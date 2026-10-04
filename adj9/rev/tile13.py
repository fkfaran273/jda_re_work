"""tile13.py - analyze the #0 tile across ALL 13 samples as a 4-word system.

Samples: 10 from all_signings.json + 3 from det_full.json (2 unique + 1 dup).
Fact: #0 = W0 at [0], then (C1 C2 C3 W1) cycled 8x for [1..33] (or 8x+3 for 36).
      als-4bce691e/det-4bce691e: prefix=2 -> [W0 W0' C1 C2 C3 W1 ...] 6 distinct.

Test for each sample:
 1. Full word list of #0.
 2. Do the tile words satisfy any of:
      t0 ^ t1 == t2 ^ t3        (swap invariant)
      t0 + t1 == t2 + t3
      rotl(t0,16) == t1
      etc.
 3. For sample 4bce691e, what is the extra W0' value?
 4. Tile-word pairing structure across samples: does any linear relation hold?
 5. Print each tile as 16 bytes and as LE, and as rotations.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))

M = 0xFFFFFFFF


def rol(v, n):
    return ((v << n) | (v >> (32 - n))) & M


def ror(v, n):
    return ((v >> n) | (v << (32 - n))) & M


def load_rows():
    rows = []
    for s in A:
        rows.append((s["d2"], struct.unpack(">36I", bytes.fromhex(s["d0"]))))
    return rows


def tile_info(w):
    # find (prefix, period) with smallest prefix then period
    for pre in range(0, 9):
        for per in range(1, 9):
            if all(w[i] == w[pre + (i - pre) % per] for i in range(pre, 36)):
                return pre, per
    return None, None


print("=== per-sample tile structure ===")
for tag, w in load_rows():
    pre, per = tile_info(w)
    print("%-12s prefix=%s period=%s" % (tag, pre, per))
    print("      words:", " ".join("%08x" % x for x in w))
    # test internal relations among the 4-tile words w[1..4]
    t = list(w[1:5])
    rels = []
    if t[0] ^ t[1] == t[2] ^ t[3]:
        rels.append("t0^t1==t2^t3")
    if (t[0] + t[1]) & M == (t[2] + t[3]) & M:
        rels.append("t0+t1==t2+t3")
    if t[0] ^ t[2] == t[1] ^ t[3]:
        rels.append("t0^t2==t1^t3")
    if (t[0] + t[2]) & M == (t[1] + t[3]) & M:
        rels.append("t0+t2==t1+t3")
    if rol(t[0], 16) == t[1]:
        rels.append("rol16(t0)==t1")
    if ror(t[1], 16) == t[0]:
        rels.append("ror16(t1)==t0")
    if t[3] == rol(t[2], 16):
        rels.append("rol16(t2)==t3")
    print("      relations:", rels or "none")

print()
print("=== #0 hex dump for the 3 distinct pattern families ===")
seen = set()
for tag, w in load_rows():
    key = (w[0], w[1], w[2])
    if key in seen:
        continue
    seen.add(key)
    raw = b"".join(struct.pack(">I", x) for x in w)
    print("%-12s: %s" % (tag, raw.hex()))

print()
print("=== 4bce691e special case (6 distinct) ===")
for tag, w in load_rows():
    if tag == "4bce691e":
        for i, x in enumerate(w):
            print("   [%2d] %08x" % (i, x))
        break
