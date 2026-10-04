"""d2_probe.py - is #2 (4 B, per-signing) a checksum/digest of signing material?

10 real samples.  Candidates: crc32/adler32/fnv1a/java-hashCode and the leading
dwords of md5/sha1/sha256/blake2 over (claims), (#0), (#4), (#0+#4), claims-length,
and #0's tile, in a few concatenation orders.
"""
import binascii
import hashlib
import json
import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))


def fnv1a(b):
    h = 0x811C9DC5
    for c in b:
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    return h


def java_hash(b):
    h = 0
    for c in b:
        h = (31 * h + c) & 0xFFFFFFFF
    return h


def be_dwords(x):
    raw = bytes.fromhex(x)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, len(raw), 4)]


inputs = {}
for i, x in enumerate(S):
    claims = bytes.fromhex(x["d10"])
    d0 = bytes.fromhex(x["d0"])
    d4 = bytes.fromhex(x["d4"])
    d7 = struct.pack(">I", int(x["d7"], 16))
    inputs[i] = {
        "d10": claims, "d0": d0, "d4": d4, "d7": d7,
        "d0tile": b"".join(struct.pack(">I", w) for w in be_dwords(x["d0"])[1:5]),
        "d10trunc": claims[:64],
    }

TARGET = [int(x["d2"], 16) for x in S]
print("targets #2:", ["%08x" % t for t in TARGET])

FUNCS = {
    "crc32": lambda b: zlib.crc32(b) & 0xFFFFFFFF,
    "adler32": lambda b: zlib.adler32(b) & 0xFFFFFFFF,
    "fnv1a": fnv1a,
    "java_hash": java_hash,
}
DIGESTS = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256,
           "blake2s": hashlib.blake2s}

print()
print("--- single-input candidates ---")
hits = 0
for name, fn in FUNCS.items():
    for ik in inputs[0]:
        ok = all(fn(inputs[i][ik]) == TARGET[i] for i in range(len(S)))
        if ok:
            print("  MATCH  %s(%s)" % (name, ik))
            hits += 1
for name, fn in DIGESTS.items():
    for ik in inputs[0]:
        for off in (0, 4, 8):
            ok = all(int.from_bytes(fn(inputs[i][ik]).digest()[off:off + 4], "big") ==
                     TARGET[i] for i in range(len(S)))
            if ok:
                print("  MATCH  %s(%s)[%d:be]" % (name, ik, off))
                hits += 1
            ok2 = all(int.from_bytes(fn(inputs[i][ik]).digest()[off:off + 4], "little") ==
                      TARGET[i] for i in range(len(S)))
            if ok2:
                print("  MATCH  %s(%s)[%d:le]" % (name, ik, off))
                hits += 1
print("single-input hits:", hits)

print()
print("--- is #2 correlated with claims length / #7? ---")
for i in range(len(S)):
    print("  [%d] #2=%08x  claims=%dB  d7=%d" %
          (i, TARGET[i], len(inputs[i]["d10"]), int(S[i]["d7"], 16)))

print()
print("--- pairwise: #2 vs dword i of #0 / #4 (is it a slice?) ---")
for i in range(len(S)):
    print("  [%d] #2=%08x  d0[0]=%08x d0[1]=%08x  d4[0]=%08x d4[7]=%08x" %
          (i, TARGET[i], be_dwords(S[i]["d0"])[0], be_dwords(S[i]["d0"])[1],
           be_dwords(S[i]["d4"])[0], be_dwords(S[i]["d4"])[7]))