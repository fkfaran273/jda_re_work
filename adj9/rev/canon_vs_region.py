"""canon_vs_region.py - is the region derived from the CANONICAL STRING?

The canonical string (HMAC input, ~1355 B) is what the server can rebuild from
the request. We tested digests of CLAIMS (0 hits) but never of the CANONICAL.
If W0/T0/T1/#2/#4 come from the canonical, the server CAN verify the region.
"""
import hashlib
import json
import os
import re
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))

# the canonical string from the golden capture
W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))
si = W["sign_inputs"][W["golden_sign_input_idx"]]
val = {}
for part in si["order"].split("\x02"):
    if "\x01" in part:
        k, v = part.split("\x01", 1)
        val[k] = v

canon = si["order"]
print("canonical len: %d" % len(canon))
print("canonical head: %r" % canon[:120])

# the golden row's region (row 7 = fb1a8296 / W0=13271271)
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
row = [r for r in A if r["d2"] == "fb1a8296"][0]
d0 = [struct.unpack(">I", bytes.fromhex(row["d0"][i:i+8]))[0] for i in range(0, 288, 8)]
d4 = [struct.unpack(">I", bytes.fromhex(row["d4"][i:i+8]))[0] for i in range(0, 64, 8)]
d2 = int(row["d2"], 16)
print("row W0=%08x d2=%08x" % (d0[0], d2))

targets = {"W0": d0[0], "T0": d0[1], "T1": d0[2], "T2": d0[3], "T3": d0[4],
           "T0v": d0[5], "a0": d4[0], "a1": d4[1], "a6": d4[6], "a7": d4[7],
           "d2": d2}

# digest battery over the canonical string (and variants)
bases = {
    "canon": canon.encode("latin1"),
    "canon_nopad": canon.encode("latin1").rstrip(b"\x00"),
    "vals_only": "".join(val[k] for k in sorted(val)).encode("latin1"),
}
digests = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256,
           "sha512": hashlib.sha512, "blake2s": hashlib.blake2s}

hits = 0
for bname, b in bases.items():
    for dname, dfn in digests.items():
        h = dfn(b).digest()
        for off in range(0, len(h) - 3, 4):
            w = struct.unpack(">I", h[off:off+4])[0]
            for tname, tv in targets.items():
                if w == tv:
                    print("HIT %s = %s(%s)[%d]" % (tname, dname, bname, off))
                    hits += 1
    crc = zlib.crc32(b) & 0xFFFFFFFF
    for tname, tv in targets.items():
        if crc == tv:
            print("HIT %s = crc32(%s)" % (tname, bname))
            hits += 1

print("canonical-digest hits: %d" % hits)

# also: do the region words appear LITERALLY anywhere in the canonical or values?
hits2 = 0
for tname, tv in targets.items():
    pat = struct.pack(">I", tv)
    if pat in canon.encode("latin1"):
        print("LITERAL BE %s in canonical" % tname)
        hits2 += 1
    patle = struct.pack("<I", tv)
    if patle in canon.encode("latin1"):
        print("LITERAL LE %s in canonical" % tname)
        hits2 += 1
    hexs = b"%08x" % tv
    if hexs in canon.encode("latin1"):
        print("HEX %s in canonical" % tname)
        hits2 += 1
print("literal hits: %d" % hits2)
if hits == 0 and hits2 == 0:
    print("=> region is NOT derived from the canonical string")