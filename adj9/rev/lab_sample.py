"""lab_sample.py - FIRST fully-labelled region sample.

The live EMIT plane (harvest_out.json) contains, per mint:
  * every descriptor buffer as its own stream (word 0 = byte length)
  * the final 192-byte blob (written word-by-word)
We know this mint's H (1..32) and its map (47 pairs) exactly, so we can
(a) invert the blob header to recover the signing second, and
(b) test whether the region words are derivable from (map, H, second).
"""
import base64
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import make_header

d = json.load(open(os.path.join(HERE, "harvest_out.json"), encoding="utf-8"))
blob = base64.b64decode(d["blobB64"])
H = base64.b64decode(d["hB64"])
pairs = [tuple(p) for p in d["mapPairs"]]
bd = list(struct.unpack("<48I", blob))
print("blob   :", blob.hex())
print("H      :", H.hex())
print("map    : %d pairs" % len(pairs))

# ---- 1. invert header -> second -------------------------------------------
print()
print("--- header inversion ---")
found = []
for sec in range(1789800000, 1789900000):
    if make_header(sec) == blob[:16]:
        found.append(sec)
print("seconds matching blob[:16]:", found)

# ---- 2. descriptor streams -------------------------------------------------
S = {}
for q, n, v in d["emits"]:
    S.setdefault(q, {})[n] = v
streams = []
for q, m in S.items():
    ns = sorted(m)
    streams.append((q, ns, [m[n] for n in ns]))
streams.sort(key=lambda s: -len(s[1]))
print()
print("--- streams (q, slots, word0, whole) ---")
for q, ns, vs in streams:
    w0 = vs[0]
    tag = ""
    if len(vs) == 48 and struct.pack("<48I", *vs) == blob:
        tag = " == BLOB"
    if ns[0] == 0 and w0 in (0x90, 0xc0, 0x168, 0x150):
        tag += " len-word=0x%x" % w0
    print("q=%-12d slots=%-4d n=%-3d..%-3d w0=%08x%s" % (q, len(ns), ns[0], ns[-1], w0, tag))

# ---- 3. identify #0 / #4 / #2 / #7 ----------------------------------------
print()
print("--- identification vs golden fin_descs shapes ---")
d0 = None
for q, ns, vs in streams:
    if len(vs) == 36 and vs[0] == 0x90:
        d0 = vs
        print(" #0 candidate q=%d  hex=%s" % (q, b"".join(struct.pack("<I", x) for x in vs[1:]).hex()))
for q, ns, vs in streams:
    if len(vs) == 8 and ns[0] == 0:
        print(" #4 candidate q=%d  hex=%s" % (q, b"".join(struct.pack("<I", x) for x in vs).hex()))
for q, ns, vs in streams:
    if len(vs) == 1:
        print(" #? single q=%-12d %08x" % (q, vs[0]))

# ---- 4. derivation battery -------------------------------------------------
print()
print("--- derivation battery: is the region a function of (map,H,second)? ---")
claims = "".join("%s=%s," % (k, v) for k, v in pairs).encode()

def digs(b):
    yield "sha256", hashlib.sha256(b).digest()
    yield "sha1", hashlib.sha1(b).digest()
    yield "md5", hashlib.md5(b).digest()
    yield "blake2s", hashlib.blake2s(b).digest()

if d0:
    W0 = d0[1]
    tile = d0[2:6]
    print("#0: W0=%08x tile=%s" % (W0, ["%08x" % x for x in tile]))
    tile_bytes = b"".join(struct.pack("<I", x) for x in tile)
    print("    tile hex (LE):", tile_bytes.hex())
    ins = {"H": H, "claims": claims, "claims+H": claims + H, "H+claims": H + claims}
    for sec in found[:1]:
        ins["sec_be32"] = struct.pack(">I", sec)
        ins["sec_le32"] = struct.pack("<I", sec)
    print("    --- tile as digest of an input? ---")
    for nm, dig in digs(tile_bytes):
        for inm, ib in ins.items():
            if dig == ib[:len(dig)]:
                print("      HIT", nm, inm)
    print("    --- tile words as digests of inputs? ---")
    for inm, ib in ins.items():
        for nm, dig in digs(ib):
            w = list(struct.unpack("<%dI" % (len(dig) // 4), dig))
            if tile[0] in w or W0 in w:
                print("      HIT(%s of %s): %s" % (nm, inm, ["%08x" % x for x in w]))
    print("    --- tile words as first words of a bionic rand(second) stream? ---")
    for sec in found[:1]:
        st = sec & 0xFFFFFFFF
        r = [st] + [0] * 33
        for i in range(1, 31):
            hi = r[i - 1] // 127773
            lo = r[i - 1] - hi * 127773
            w = 16807 * lo - 2836 * hi
            r[i] = w + 2147483647 if w < 0 else w
        f, b_ = 3, 0
        out = []
        for _ in range(340):
            v = (r[f] + r[b_]) & 0xFFFFFFFF
            r[f] = v
            o = v >> 1
            f = (f + 1) % 31
            b_ = (b_ + 1) % 31
            out.append(o)
        if tile[0] in out:
            print("      HIT rand-single: idx", out.index(tile[0]))
        hits = 0
        for i in range(len(out) - 4):
            if out[i:i + 4] == list(tile):
                hits += 1
                print("      HIT rand-tile at idx", i)
        print("      rand tile-run hits:", hits)

# ---- 5. where in the blob do the streams land? -----------------------------
print()
print("--- descriptor -> blob placement ---")
for q, ns, vs in streams:
    if ns[0] != 0 or len(vs) < 2:
        continue
    payload = b"".join(struct.pack("<I", x) for x in vs[1:])
    off = blob.find(payload[:16])
    print("q=%-12d payload=%-4dB first16@blob=%-5s" %
          (q, len(payload), off))