"""digest_in_blob.py - does the blob contain a DIGEST of the claims?

The server can't verify H (key2 is TEE-only) and can't know the random region.
But if the body embeds something derived from the CLAIMS (which the server can
recompute from the request params), that IS verifiable — and it would be the gate.

Test: from the app_reg.json capture (genuine signing with known claims + blob),
look for SHA-256/SHA-1/MD5/crc32 of the claims/canonical inside the blob body.
"""
import hashlib
import json
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
d = json.load(open(os.path.join(HERE, "app_reg.json"), encoding="utf-8"))


def segment(rows):
    segs, cur = [], {}
    for st, n, v in rows:
        if n == 0 and st in cur and cur[st]:
            segs.append(cur)
            cur = {}
        cur.setdefault(st, {})[n] = v
    segs.append(cur)
    return segs


segs = segment([(st, n, v) for st, n, v in d["emits"]])
seg = segs[0]


def pick(cnt):
    return [[m[i] for i in sorted(m)] for m in seg.values() if len(m) == cnt]


b = lambda vs: b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in vs)

# claims (#10): 90 or 97 words in seg0
claims = None
for c in (90, 97, 96, 84):
    p = pick(c)
    if p:
        claims = b(p[0])
        break
print("claims len:", len(claims))
print("claims head:", claims[:60])

# the blob: find the 48-word output stream whose words carry the header law
from header_gen import make_header
sec = None
# search all segments for a 48-word stream starting with a valid header
blob = None
for k, s in enumerate(segs):
    for st, m in s.items():
        vs = [m[i] for i in sorted(m)]
        if len(vs) == 48:
            head = b(vs[:4])
            for candidate in range(1789900000, 1790000000):
                if make_header(candidate) == head:
                    sec = candidate
                    blob = b(vs)
                    break
        if blob:
            break
    if blob:
        break
print("blob found:", bool(blob), "sec:", sec)

if blob:
    print("blob:", blob.hex())
    print()
    # digest battery: does any digest of the claims appear in the blob?
    cands = {}
    for name, fn in [("sha256", hashlib.sha256), ("sha1", hashlib.sha1),
                     ("md5", hashlib.md5), ("sha512", hashlib.sha512),
                     ("blake2s", hashlib.blake2s)]:
        for label, data in [("claims", claims),
                            ("claims_padded", claims + b"\0" * (-len(claims) % 4)),
                            ("claims_trim", claims.rstrip(b"\0"))]:
            h = fn(data).digest()
            cands["%s(%s)" % (name, label)] = h
    cands["crc32"] = struct.pack(">I", zlib.crc32(claims) & 0xFFFFFFFF)
    cands["adler32"] = struct.pack(">I", zlib.adler32(claims) & 0xFFFFFFFF)

    hits = []
    for name, h in cands.items():
        if h in blob:
            hits.append(name + " (full)")
        # also check windows / word forms
        for wl in (4, 8, 16):
            for off in range(0, len(h) - wl + 1, 4):
                chunk = h[off:off + wl]
                if chunk in blob:
                    hits.append("%s window@%d" % (name, off))
    print("DIGEST HITS:", hits if hits else "NONE")
    print()
    # also: any 4-word window of the blob equal to a digest window?
    print("blob body words:", ["%08x" % w for w in struct.unpack(">48I", blob)])
