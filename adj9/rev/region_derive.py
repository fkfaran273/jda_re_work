# region_derive.py - can #0's 5 values / #2 / #4 be DERIVED from the payload?
#
# region_struct.log (new): #0 is 144 B but carries only FIVE distinct dwords, laid
# out as [X, C1, C2, C3] x 9 (g0 has X=W0, g1..g8 all X=W1). #2 is 1 dword, #4 is 8
# dwords. So the "region" is ~14 dwords of real entropy, not 176 random bytes.
#
# det_full.json keeps the FULL payload for each segmented signing, so for the first
# time the region can be tested against the payload it signed: hashes, Java
# hashCode, the Random3 PRNG, and word-level statistics.
import hashlib
import json
import os
import re
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import Random3

DET = json.load(open(os.path.join(HERE, "det_full.json"), encoding="utf-8"))
FD = json.load(open(os.path.join(HERE, "fin_descs.json"), encoding="utf-8"))


def d0vals(d0hex):
    w = struct.unpack(">36I", bytes.fromhex(d0hex)[:144])
    return w[0], w[4], w[1], w[2], w[3]        # W0, W1, C1, C2, C3


def java_hash(s):
    h = 0
    for ch in s:
        h = (31 * h + ord(ch)) & 0xFFFFFFFF
    return h


def fnv1a(b):
    h = 0x811c9dc5
    for c in b:
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    return h


FUNCS = {
    "crc32": lambda b: zlib.crc32(b) & 0xFFFFFFFF,
    "adler32": lambda b: zlib.adler32(b) & 0xFFFFFFFF,
    "fnv1a": fnv1a,
    "md5[:4]": lambda b: int.from_bytes(hashlib.md5(b).digest()[:4], "big"),
    "md5[-4:]": lambda b: int.from_bytes(hashlib.md5(b).digest()[-4:], "big"),
    "sha1[:4]": lambda b: int.from_bytes(hashlib.sha1(b).digest()[:4], "big"),
    "sha256[:4]": lambda b: int.from_bytes(hashlib.sha256(b).digest()[:4], "big"),
    "sha256[-4:]": lambda b: int.from_bytes(hashlib.sha256(b).digest()[-4:], "big"),
    "javahash": lambda b: java_hash(b.decode("latin1")),
    "len": lambda b: len(b) & 0xFFFFFFFF,
    "sum(dw)": lambda b: sum(struct.unpack(">%dI" % (len(b) // 4), b)) & 0xFFFFFFFF,
}

print("=== sample: does a payload hash equal any region dword? ===")
for title, key in (("golden", None), ("det[1]", 1), ("det[2]", 2)):
    s = DET[key] if key is not None else DET[0]
    payload = bytes.fromhex(s["payload"])
    W0, W1, C1, C2, C3 = d0vals(s["d0"])
    d2 = int(s["d2"], 16) if isinstance(s["d2"], str) else s["d2"]
    d4 = [int(s["d4"][i * 8:i * 8 + 8], 16) for i in range(8)]
    targets = {"W0": W0, "W1": W1, "C1": C1, "C2": C2, "C3": C3, "#2": d2}
    for i, v in enumerate(d4):
        targets["#4.dw%d" % i] = v
    print("\n  --- %s  payload=%d B  ca=%s" % (title, len(payload),
                                               s.get("created_at")))
    print("      W0=%08x W1=%08x C1=%08x C2=%08x C3=%08x #2=%08x"
          % (W0, W1, C1, C2, C3, d2))
    for name, fn in FUNCS.items():
        try:
            v = fn(payload) & 0xFFFFFFFF
        except Exception:
            continue
        for tn, tv in targets.items():
            if v == tv:
                print("      *** %s(payload) == %s ***" % (name, tn))
    # Random3 with the header second as seed
    sec = s.get("second")
    if sec:
        R = Random3(sec)
        outs = [R.next() for _ in range(2000)]
        for tn, tv in targets.items():
            if tv in outs:
                print("      *** Random3(%d) outputs %s at draw %d ***"
                      % (sec, tn, outs.index(tv)))

print("\n=== relations among the region values ===")
for title, key in (("golden", None), ("det[1]", 1), ("det[2]", 2)):
    s = DET[key] if key is not None else DET[0]
    W0, W1, C1, C2, C3 = d0vals(s["d0"])
    d2 = int(s["d2"], 16) if isinstance(s["d2"], str) else s["d2"]
    d4 = [int(s["d4"][i * 8:i * 8 + 8], 16) for i in range(8)]
    vals = {"W0": W0, "W1": W1, "C1": C1, "C2": C2, "C3": C3, "#2": d2}
    for i, v in enumerate(d4):
        vals["#4.%d" % i] = v
    print("  %s: xor(W0,W1)=%08x xor(C1,C2)=%08x xor(C2,C3)=%08x sym=%08x"
          % (title, W0 ^ W1, C1 ^ C2, C2 ^ C3, C1 ^ C2 ^ C3))

print("\n=== share values ACROSS signings? ===")
sets = {}
for i, s in enumerate(DET):
    W0, W1, C1, C2, C3 = d0vals(s["d0"])
    sets["det[%d]" % i] = {W0, W1, C1, C2, C3}
for a in sets:
    for b in sets:
        if a < b:
            print("  %s vs %s shared: %s" % (a, b, sets[a] & sets[b] or "none"))

print("\n=== #4 head as 16-bit words (flagged structure?) ===")
for i, s in enumerate(DET):
    w = struct.unpack(">16H", bytes.fromhex(s["d4"]))
    print("  det[%d] %s" % (i, " ".join("%04x" % x for x in w)))