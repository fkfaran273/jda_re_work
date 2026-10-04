"""region_fit.py - is #0/#2/#4 a KEYED function of the canonical map?

Facts to fit (rev/region_struct.log, rev/det_full.json, rev/wh4_records.json):
  * same map + same second       -> identical region (slice 116)
  * region dwords are NOT ROM constants (rev/const_scan.log)
  * no unkeyed hash / Random3 draw matches any region dword (region_derive.log)

That leaves a keyed construction. This script builds (canonical, H, region)
triples from the captures and tests HMAC/hash families:
    key  in {H(arg3), captured_H, key2_hex, alphabet soup}
    msg  in {canonical, canonical+fields, descriptor bytes, #10}
    alg  in {HMAC-SHA256, SHA256, SHA1, MD5, HMAC-SHA1}
    out  compared against d4[8:32], d4[16:32], d2, d0 dwords, and 32-byte windows.
"""
import hashlib
import hmac
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def hexb(h):
    return bytes.fromhex(h)


W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))
MAT = {}
p = os.path.join(HERE, "adj9_material.json")
if os.path.exists(p):
    MAT = json.load(open(p, encoding="utf-8"))

# canonical strings (in the SDK's own order) + their sign_input blobs
canon = []
for si in W.get("sign_inputs", []):
    order = si.get("order", "")
    canon.append(order)
Hs = [x["hex"] for x in W.get("mac_doFinal", [])]
print("canonicals: %d   H values: %d (%d distinct)" % (len(canon), len(Hs),
                                                       len(set(Hs))))

captured_H = []
if isinstance(MAT.get("captured_H"), dict):
    captured_H = list(MAT["captured_H"].values())
elif isinstance(MAT.get("captured_H"), list):
    captured_H = MAT["captured_H"]
keys = {"H%d" % i: hexb(h) for i, h in enumerate(set(Hs))}
for i, h in enumerate(captured_H):
    if isinstance(h, str):
        try:
            keys["capH%d" % i] = hexb(h)
        except Exception:
            pass
for nm in ("key2_hex", "key2", "key_hex"):
    v = MAT.get(nm)
    if isinstance(v, str) and len(v) >= 32:
        try:
            keys["mat_" + nm] = hexb(v)
        except Exception:
            pass
print("keys: %s" % {k: v[:6].hex() + "…" for k, v in keys.items()})

# regions
DET = json.load(open(os.path.join(HERE, "det_full.json"), encoding="utf-8"))
regions = []
for i, s in enumerate(DET):
    d4 = hexb(s["d4"])
    regions.append({"tag": "det[%d]" % i, "d4": d4,
                    "d2": struct.pack(">I", s["d2"]),
                    "d0": hexb(s["d0"]),
                    "canon": s.get("payload")})
print("regions: %d" % len(regions))

ALGS = {
    "hmac-sha256": lambda k, m: hmac.new(k, m, hashlib.sha256).digest(),
    "hmac-sha1": lambda k, m: hmac.new(k, m, hashlib.sha1).digest(),
    "hmac-md5": lambda k, m: hmac.new(k, m, hashlib.md5).digest(),
    "sha256": lambda k, m: hashlib.sha256(k + m).digest(),
    "sha256rev": lambda k, m: hashlib.sha256(m + k).digest(),
    "sha1": lambda k, m: hashlib.sha1(k + m).digest(),
    "md5": lambda k, m: hashlib.md5(k + m).digest(),
    "md5rev": lambda k, m: hashlib.md5(m + k).digest(),
}

# message candidates per region
def msgs_for(r):
    c = r["canon"]
    if isinstance(c, str):
        c = c.encode("latin1")
    out = {}
    if c:
        out["canon"] = c
        out["canon_nul"] = c + b"\x00"
        out["canon_lf"] = c + b"\n"
    out["d0"] = r["d0"]
    out["d2"] = r["d2"]
    out["d4"] = r["d4"]
    out["d2+d0"] = r["d2"] + r["d0"]
    return out


hits = 0
tested = 0
for r in regions:
    msgs = msgs_for(r)
    targ = {"#4": r["d4"], "#4[8:]": r["d4"][8:], "#4[16:]": r["d4"][16:],
            "#2": r["d2"], "#0[0:32]": r["d0"][:32], "#0[16:48]": r["d0"][16:48],
            "#0[112:144]": r["d0"][112:144]}
    for kn, kb in keys.items():
        for mn, mb in msgs.items():
            for an, fn in ALGS.items():
                try:
                    out = fn(kb, mb)
                except Exception:
                    continue
                tested += 1
                for tn, tv in targ.items():
                    if not tv:
                        continue
                    if out[:len(tv)] == tv or out[-len(tv):] == tv or tv in out:
                        print("HIT %-6s %-14s key=%-8s msg=%-10s -> %s"
                              % (an, r["tag"], kn, mn, tn))
                        hits += 1
print("tested %d combinations, hits %d" % (tested, hits))

# also: are the region dwords related to each other by a simple word mixer?
print("\n=== intra-region relations (golden) ===")
g = regions[0]
w = struct.unpack(">8I", g["d4"])
print("d4 words: %s" % " ".join("%08x" % x for x in w))
print("xor chain:", " ".join("%08x" % (w[i] ^ w[i + 1]) for i in range(7)))
print("done")