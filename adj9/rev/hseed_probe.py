"""hseed_probe.py - is the 56-byte region seeded FROM H or (H,second)?

Untried family: H (32 B, per-signing, device keystore MAC over the map) as the
PRNG seed.  Tests per clean row (pair_h3 0,1,4,5,6,7):
  * Random3(H_word) raw + xor-pair streams contain W0/tile/#2/#4 words?
  * java.util.Random(H_word / second / nsign_ts) next(32) stream contains them?
Seeds tried BE + LE + masked variants; 8000 draws each; reports exact hits.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import Random3

R = [r for r in json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))
     if r["H"] and r["i"] in (0, 1, 4, 5, 6, 7)]
print("rows:", [(r["i"], r["second"]) for r in R])


def be_words(hexs, n):
    raw = bytes.fromhex(hexs)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 4 * n, 4)]


def rev32(v):
    return int.from_bytes(v.to_bytes(4, "big"), "little")


JMASK = (1 << 48) - 1
JMULT = 0x5DEECE66D


def java_stream(seed48, n=8000):
    s = (seed48 ^ JMULT) & JMASK
    out = []
    for _ in range(n):
        s = (s * JMULT + 0xB) & JMASK
        out.append((s >> 16) & 0xFFFFFFFF)
    return out


def r3_streams(seed, n=4000):
    Rr = Random3(seed)
    raw = [Rr.next() for _ in range(2 * n)]
    pairs = [raw[2 * k] ^ raw[2 * k + 1] for k in range(n)]
    return raw, pairs


total = 0
for r in R:
    Hb = bytes.fromhex(r["H"])
    Hw_be = [int.from_bytes(Hb[i:i + 4], "big") for i in range(0, 32, 4)]
    Hw_le = [rev32(w) for w in Hw_be]
    d0 = be_words(r["d0"], 5)
    W0, tile = d0[0], d0[1:5]
    tgt2 = int(r["d2"], 16)
    tgt4 = be_words(r["d4"], 8)
    targets = {"W0": W0, "#2": tgt2}
    for k in range(4):
        targets["tile%d" % k] = tile[k]
    for k in range(8):
        targets["#4[%d]" % k] = tgt4[k]
    tset = set(targets.values())
    seeds = {}
    for j, w in enumerate(Hw_be):
        seeds["Hbe%d" % j] = w
        seeds["Hle%d" % j] = Hw_le[j]
        seeds["Hbe%d&7f" % j] = w & 0x7FFFFFFF
    sec = r["second"]
    ts = r["nsign_ts"]
    seeds["sec"] = sec & 0xFFFFFFFF
    seeds["sec_lo31"] = sec & 0x7FFFFFFF
    seeds["ts_lo32"] = ts & 0xFFFFFFFF
    seeds["ts_lo31"] = ts & 0x7FFFFFFF
    found = []
    for snm, sd in seeds.items():
        raw, pairs = r3_streams(sd)
        sset_raw, sset_pair = set(raw), set(pairs)
        hit = [nm for nm, v in targets.items() if v in sset_raw]
        if hit:
            found.append((snm, "r3raw", hit))
        hit2 = [nm for nm, v in targets.items() if v in sset_pair]
        if hit2:
            found.append((snm, "r3pair", hit2))
        js = java_stream(sd & JMASK)
        sset_j = set(js)
        hit3 = [nm for nm, v in targets.items() if v in sset_j]
        if hit3:
            found.append((snm, "java", hit3))
    total += sum(len(f[2]) for f in found)
    print("[%d] sec=%d %s" % (r["i"], sec, found if found else "none"))
print()
print("total H/seed-stream hits:", total)
