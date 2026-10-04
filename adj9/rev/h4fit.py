"""h4fit.py - H transforms against #4, and the H-uniqueness sanity check.

Battery: H xor-folded/added to 8 words; md5/sha1/sha256/blake2s of H by itself; the
first 8 dwords (LE and BE) of those digests; plus "is H itself reused (would break
the (H,second) uniqueness the region seems to need)".
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
R = [r for r in json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))
     if r["H"] and r["i"] in (4, 5, 6, 7, 0, 1)]
print("rows:", [(r["i"], r["second"]) for r in R])

# uniqueness: no two rows share H (else an (H,second)-only function could still collide)
Hv = [r["H"] for r in R]
print("distinct H: %d/%d" % (len(set(Hv)), len(Hv)))


def be(hexs, n):
    raw = bytes.fromhex(hexs)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 4 * n, 4)]


def bfold(ws, n=8):
    out = [0] * n
    for i, w in enumerate(ws):
        out[i % n] ^= w
    return out


hits = 0
for r in R:
    Hb = bytes.fromhex(r["H"])
    Hw = [int.from_bytes(Hb[i:i + 4], f) for f in ("big", "little") for i in range(0, 32, 4)]
    tgt4 = be(r["d4"], 8)
    cands = {}
    cands["hmac(H,claims)"] = __import__("hmac").new(
        Hb, bytes.fromhex(json.load(open(os.path.join(HERE, "all_signings.json"),
                                         encoding="utf-8"))[r["i"]]["d10"]), hashlib.sha256).digest()
    for nm, fn in (("sha256", hashlib.sha256), ("sha1", hashlib.sha1),
                   ("md5", hashlib.md5), ("blake2s", hashlib.blake2s)):
        dg = fn(Hb).digest()
        cands[nm + "-be"] = dg
        cands[nm + "-le"] = dg[::-1]
    found = []
    for nm, dg in cands.items():
        for k in range(0, len(dg) - 32 + 1, 4):
            if [int.from_bytes(dg[k + 4 * j:k + 4 * j + 4], "big") for j in range(8)] == tgt4:
                found.append(nm + "[%d]be" % k)
            if [int.from_bytes(dg[k + 4 * j:k + 4 * j + 4], "little") for j in range(8)] == tgt4:
                found.append(nm + "[%d]le" % k)
    for nm, w in (("hw-be", Hw[:8]), ("hw-le", Hw[8:])):
        if bfold(w) == tgt4:
            found.append(nm + "-fold8")
    hits += len(found)
    print("[%d] %s" % (r["i"], found or "none"))
print("total hits:", hits)