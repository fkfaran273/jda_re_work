"""blob_sections.py - what are the blob's TWO sections, and is the 2nd derivable?

Slice 121: blob = [144B section][48B section]. The 144B section starts with the
header. What is the 48B section? If it is a digest/MAC of the claims (which the
server CAN rebuild), that is the gate.
"""
import hashlib
import json
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))

P3 = json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
BYD2 = {r["d2"]: r for r in A}

for row in P3[:3]:
    blob = bytes.fromhex(row["blob"])
    src = BYD2.get(row["d2"])
    if not src:
        continue
    claims = bytes.fromhex(src["d10"])
    print("=== d2=%s sec=%s blob=%s" % (row["d2"], row["second"], blob[:16].hex()))
    print("  sec1 (0..143):  %s" % blob[:16].hex())
    print("  sec2 (144..191):%s" % blob[144:].hex())
    print("  sec2 dwords:    %s" % ["%08x" % w for w in struct.unpack(">12I", blob[144:])])
    print("  claims len=%d head=%s" % (len(claims), claims[:32].hex()))

    # is sec2 a digest of claims / canonical-ish strings?
    cands = {}
    for name, fn in [("md5", hashlib.md5), ("sha1", hashlib.sha1),
                     ("sha256", hashlib.sha256), ("sha512", hashlib.sha512),
                     ("blake2s", hashlib.blake2s), ("sha3_256", hashlib.sha3_256)]:
        for lab, data in [("claims", claims),
                          ("claims_trim", claims.rstrip(b"\x00")),
                          ("claims_pad", claims + b"\0" * (-len(claims) % 4)),
                          ("claims+sec", claims + str(row["second"]).encode()),
                          ("sec+claims", str(row["second"]).encode() + claims)]:
            cands["%s(%s)" % (name, lab)] = fn(data).digest()
    cands["crc32_claims"] = struct.pack(">I", zlib.crc32(claims) & 0xFFFFFFFF)
    cands["adler32_claims"] = struct.pack(">I", zlib.adler32(claims) & 0xFFFFFFFF)

    hits = []
    for name, h in cands.items():
        if h in blob:
            hits.append(name + " FULL")
        for off in range(0, len(h) - 3, 4):
            w4 = h[off:off + 4]
            if w4 in blob:
                hits.append("%s w@%d" % (name, off))
    print("  digest hits: %s" % (hits if hits else "NONE"))
    print()