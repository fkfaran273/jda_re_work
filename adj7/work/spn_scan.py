"""spn_scan.py — locate chunk outputs in adj7s4_stores7.txt and extract the
16-B round-state chain around chunk 0.

    python spn_scan.py
"""
import os
import struct
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))

BLOB = bytes.fromhex(json.load(open(os.path.join(WORK, "adj7s4_out7.json")))
                     ["out_hex"]) if False else None
import json
BLOB = bytes.fromhex(json.load(open(os.path.join(WORK, "adj7s4_out7.json")))
                     ["out_hex"])
IV = BLOB[:16]
BODY = BLOB[16:272]
TAG = BLOB[272:304]
print("IV", IV.hex())
print("body[0:16]", BODY[:16].hex())


def swap4(b):
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b) - 3, 4))


BODY_SW = swap4(BODY)
IV_SW = swap4(IV)

# ---- load stores ----
stores = []          # (idx, pc, addr, size, val)
with open(os.path.join(WORK, "adj7s4_stores7.txt")) as f:
    for ln in f:
        p = ln.split()
        if len(p) >= 5:
            stores.append((int(p[0]), int(p[1], 16), int(p[2], 16),
                           int(p[3]), int(p[4], 16)))
print("stores:", len(stores))

# pc histogram
pcc = Counter(s[1] for s in stores)
print("top PCs:", [(hex(pc), n) for pc, n in pcc.most_common(12)])

# ---- find where body dwords appear (as written values, size 4) ----
# wire chunk0 dwords (BE interpretation of blob bytes): blob[16:20]=.. as
# stored dword value: the write value is the raw 32-bit stored; on LE memory
# value v at addr a means bytes v&0xff etc.
wire_d0 = struct.unpack(">I", BODY[0:4])[0]        # BE view
le_d0 = struct.unpack("<I", BODY[0:4])[0]
sw_d0 = struct.unpack("<I", BODY_SW[0:4])[0]
print("wire BE d0 %#x  LE d0 %#x  swapped d0 %#x" % (wire_d0, le_d0, sw_d0))

for nm, want in (("wireBE", wire_d0), ("wireLE", le_d0), ("swapped", sw_d0)):
    hits = [(i, pc, a) for i, (idx, pc, a, s, v) in enumerate(stores)
            if s == 4 and v == want]
    print(nm, "hits:", len(hits), hits[:6])

# ---- memory image replay: find final direct body location ----
mem = {}
for idx, pc, a, s, v in stores:
    for k in range(s):
        mem[a + k] = (v >> (8 * k)) & 0xFF
# search mem for BODY and BODY_SW
def find_seq(mem, seq):
    n = len(seq)
    hits = []
    keys = sorted(mem)
    # build sparse check: use first key of seq occurrence scan via sliding
    # too slow for 341k*... instead scan addresses
    for a in range(min(mem), max(mem) - n):
        ok = True
        for j in range(0, n, 1):
            if mem.get(a + j) != seq[j]:
                ok = False
                break
        if ok:
            hits.append(a)
    return hits

# too slow; do it with numpy-less approach: reconstruct contiguous buffer over
# heap range 0x9000000-0x9020000
buf = bytearray(0x20000)
cov = bytearray(0x20000)
for idx, pc, a, s, v in stores:
    if 0x9000000 <= a < 0x9020000:
        for k in range(s):
            buf[a - 0x9000000 + k] = (v >> (8 * k)) & 0xFF
            cov[a - 0x9000000 + k] = 1

for nm, seq in (("BODY", BODY), ("BODY_SW", BODY_SW), ("IV", IV),
                ("IV_SW", IV_SW), ("TAG", TAG)):
    i = bytes(buf).find(seq)
    hits = []
    while i != -1 and len(hits) < 8:
        hits.append(hex(0x9000000 + i))
        i = bytes(buf).find(seq, i + 1)
    print(nm, "in final heap image at:", hits)

# ---- timeline of last 200 stores ----
print("last 40 stores:")
for idx, pc, a, s, v in stores[-40:]:
    print("  %7d pc=%x a=%x s=%d v=%x" % (idx, pc, a, s, v))
