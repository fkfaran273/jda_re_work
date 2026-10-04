"""hash_d0.py - is #0's W0 (or the C-triad) a hash of the map/H/second?

det[0] vs det[2]: SAME payload, SAME created_at, SAME MAC (mac6==mac7? check),
DIFFERENT region. So region is NOT f(map) alone. But maybe f(map, second) with
different signing seconds, or f(map, H) with different H. Pair the two:
  - det[0] <-> als[7] (same d2/fb1a8296, same d4, same d0): ONE signing.
  - det[2] <-> als[9] (same d2/4bce691e, same d4, same d0): ONE signing.
So we have 10 distinct signings. For each, test W0/C-triads against:
  crc32/adler32/fnv1a-32/Murmur-ish/Java-hashCode of (canonical, H, second).
"""
import sys
import os
import json
import struct
import zlib
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))
Hs = [bytes.fromhex(x["hex"]) for x in W["mac_doFinal"]]

print("macs distinct: %d" % len(set(h.hex() for h in Hs)))
print("sign_inputs orders distinct: %d"
      % len(set(si["order"] for si in W["sign_inputs"])))


def fnv1a(b):
    h = 0x811C9DC5
    for x in b:
        h = ((h ^ x) * 0x01000193) & 0xFFFFFFFF
    return h


def jhash(b):
    h = 0
    for x in b:
        h = (31 * h + x) & 0xFFFFFFFF
    return h


for i, s in enumerate(A):
    w0 = struct.unpack(">I", bytes.fromhex(s["d0"])[:4])[0]
    d10 = bytes.fromhex(s["d10"])
    c = zlib.crc32(d10) & 0xFFFFFFFF
    ad = zlib.adler32(d10) & 0xFFFFFFFF
    fv = fnv1a(d10)
    jh = jhash(d10)
    m = hashlib.md5(d10).digest()
    m32 = struct.unpack(">I", m[:4])[0]
    hit = {n: v for n, v in (("crc", c), ("adler", ad), ("fnv", fv),
                             ("jhash", jh), ("md5w0", m32)) if v == w0}
    print("als%d w0=0x%08x crc=0x%08x fnv=0x%08x jh=0x%08x md5=0x%08x %s"
          % (i, w0, c, fv, jh, m32, "HIT " + str(hit) if hit else ""))
print("done")
