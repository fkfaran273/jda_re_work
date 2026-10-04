"""mem_scan.py - search the builder-argument memory windows for the descriptor
structures: the repeating 16-byte tile (#0 shape), a sparse 8-dword block (#4
shape), the claim string, and the small singles (#2/#7/#5/#6).

Also inverts the new blob's header to recover the signing second.
"""
import base64
import json
import os
import struct
import sys
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import make_header

h = json.load(open(os.path.join(HERE, "harvest_out.json"), encoding="utf-8"))
blob = base64.b64decode(h["blobB64"])
bd = list(struct.unpack("<48I", blob))
print("blob:", blob.hex())
print("blob dwords:", " ".join("%08x" % x for x in bd))

sec = None
for s in range(1789820000, 1789860000):
    if make_header(s) == blob[:16]:
        sec = s
        break
print("second:", sec, "(header law:", make_header(sec) == blob[:16], ")")

d = json.load(open(os.path.join(HERE, "dmp_out.json"), encoding="utf-8"))
W = []
for x in d["dumps"]:
    W.append((x["tag"], int(x["va"], 16), base64.b64decode(x["b64"])))
print("windows:", [(t, hex(v), len(b)) for t, v, b in W])

claims_ascii = bytes.fromhex("".join("%02x" % c for c in b"KlcA"))
for tag, va, b in W:
    i = b.find(claims_ascii)
    if i >= 0:
        print("  claim string in %s at +0x%x: %r" % (tag, i, b[i:i + 64]))
    for key in (b"attribution", b"android_uuid", b"gps_adid", b"activity_kind"):
        j = b.find(key)
        if j >= 0:
            print("  %-14s in %s at +0x%x: %r" % (key.decode(), tag, j, b[j:j + 40]))

# --- structural search: 16-byte tile repeated, sparse 8-dword block ---------
def popcount(x):
    return bin(x).count("1")

print()
print("--- 16-byte repeating tiles (candidate #0) ---")
for tag, va, b in W:
    n = len(b) // 4
    w = list(struct.unpack("<%dI" % n, b))
    for start in range(0, n - 16):
        tile = w[start:start + 4]
        reps = 1
        while start + 4 * (reps + 1) <= n and w[start + 4 * reps:start + 4 * (reps + 1)] == tile:
            reps += 1
        if reps >= 5 and any(tile):
            print("  %s +0x%03x tile=%s reps=%d  (window va %#x -> buf va %#x)" %
                  (tag, start * 4, ["%08x" % t for t in tile], reps, va, va + start * 4))

print()
print("--- sparse ascending-density 8-dword blocks (candidate #4) ---")
for tag, va, b in W:
    n = len(b) // 4
    w = list(struct.unpack("<%dI" % n, b))
    for start in range(0, n - 8):
        seg = w[start:start + 8]
        pc = [popcount(x) for x in seg]
        if pc[0] <= 3 and all(pc[i] <= pc[i + 1] for i in range(7)) and pc[-1] >= 4 and sum(pc) >= 22:
            print("  %s +0x%03x pop=%s words=%s" %
                  (tag, start * 4, pc, ["%08x" % x for x in seg]))

print()
print("--- words matching blob dwords inside windows ---")
pos = {}
for i, x in enumerate(bd):
    pos.setdefault(x, []).append(i)
hits = {}
for tag, va, b in W:
    n = len(b) // 4
    for j, x in enumerate(struct.unpack("<%dI" % n, b)):
        if x in pos:
            hits.setdefault(tag, []).append((j * 4, "%08x" % x, pos[x]))
for tag in hits:
    print("  %s: %d hits" % (tag, len(hits[tag])))
    for t in hits[tag][:12]:
        print("     +0x%04x %s -> blob idx %s" % t)