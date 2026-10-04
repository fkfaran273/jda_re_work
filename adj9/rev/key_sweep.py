#!/usr/bin/env python3
"""Sweep every digest/tag observed in the trace as a candidate body key."""
import json, hashlib, re, itertools
from Crypto.Cipher import AES

T = json.load(open("../device/triples.json"))
pairs = [(bytes.fromhex(t["H"]), bytes.fromhex(t["env"])) for t in T if t["H"] and t["env"]]
BODY = [p[1][16:] for p in pairs]
HDR = [p[1][:16] for p in pairs]
APP_SHA1 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")

ev = json.load(open("../device/events.json"))
vals = set()
for e in ev:
    for f in ("hex", "hex_in", "hex_out"):
        h = e["fields"].get(f)
        if h and len(h) in (32, 48, 64, 40, 128):  # 16/24/32/20/64 bytes
            try:
                vals.add(bytes.fromhex(h))
            except Exception:
                pass
print("distinct digest-sized values from trace:", len(vals))

keys = {}
i = 0
for v in vals:
    if len(v) in (16, 24, 32):
        keys["raw%d" % i] = v
    keys["sha256_%d" % i] = hashlib.sha256(v).digest()
    i += 1

print("candidate keys:", len(keys))

def dec_ecb(k, d):
    return AES.new(k, AES.MODE_ECB).decrypt(d[:len(d) // 16 * 16])

def xorstream(k, d):
    ks = hashlib.sha256(k).digest()
    out = bytearray()
    while len(out) < len(d):
        ks = hashlib.sha256(ks).digest()
        out += ks
    return bytes(a ^ b for a, b in zip(d, out))

targets = [("H%d" % i, p[0]) for i, p in enumerate(pairs)] + [("appsha1", APP_SHA1)]
hits = 0
for name, k in keys.items():
    try:
        pt = dec_ecb(k, BODY[0])
    except Exception:
        continue
    for tn, tv in targets:
        if tv in pt:
            print("HIT-ECB", name, k.hex()[:16], tn)
            hits += 1
    pt2 = xorstream(k, BODY[0])
    for tn, tv in targets:
        if tv in pt2:
            print("HIT-SHASTREAM", name, k.hex()[:16], tn)
            hits += 1
    # 16-byte XOR mask repeated
    if len(k) == 16:
        pt3 = bytes(c ^ k[i % 16] for i, c in enumerate(BODY[0]))
        for tn, tv in targets:
            if tv in pt3:
                print("HIT-XORREP", name, k.hex()[:16], tn)
                hits += 1
print("hits:", hits)
