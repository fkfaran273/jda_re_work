"""geom_probe.py - the one hypothesis never tested: is the 56-byte region derived
from the CLAIM-STRING GEOMETRY (key lengths, value lengths, offsets inside #10)?

All 10 real signings. For each: parse the claims string into key=value pairs, build the
geometry vectors (key lengths, value lengths, entry offsets, entry lengths), then look
for those numbers inside #0 (W0 + tile), #2 and #4 -- as 32-bit dwords, 16-bit halves
or bytes -- and for simple folds (sum / xor / count) matching #2 or #4's words.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))


def be_words(hexs, n=None):
    raw = bytes.fromhex(hexs)
    if n is None:
        n = len(raw) // 4
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 4 * n, 4)]


def parse_claims(b):
    """#10 is key=value,key=value,... (comma separated); split on commas."""
    txt = b.decode("latin1")
    parts = txt.split(",")
    out = []
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            out.append((k, v))
    return out, parts


print("%-3s %-5s %-6s %-6s %-8s %s" % ("i", "entries", "sumK", "sumV", "#2", "#4[0]"))
geo = []
for i, x in enumerate(S):
    cb = bytes.fromhex(x["d10"])
    pairs, parts = parse_claims(cb)
    kl = [len(k) for k, _ in pairs]
    vl = [len(v) for _, v in pairs]
    offs, o = [], 0
    for p in parts:
        offs.append(o)
        o += len(p) + 1
    g = {"i": i, "kl": kl, "vl": vl, "offs": offs, "parts": parts,
         "sumK": sum(kl), "sumV": sum(vl), "n": len(pairs),
         "d2": int(x["d2"], 16), "d4": be_words(x["d4"], 8),
         "d0": be_words(x["d0"], 5)}
    geo.append(g)
    print("%-3d %-5d %-6d %-6d %08x %08x" %
          (i, g["n"], g["sumK"], g["sumV"], g["d2"], g["d4"][0]))

print()
print("--- do geometry numbers appear inside the region? ---")
for g in geo:
    vals = set()
    for v in g["kl"] + g["vl"] + g["offs"]:
        vals.add(v)
    # 32-bit dwords of d0/d4
    dwords = set(g["d0"][1:]) | set(g["d4"])
    halves = set()
    for d in list(dwords):
        halves.add(d >> 16)
        halves.add(d & 0xFFFF)
    bytes_ = set()
    for d in list(dwords):
        for sh in (0, 8, 16, 24):
            bytes_.add((d >> sh) & 0xFF)
    hit32 = sorted(v for v in vals if v in dwords)
    hit16 = sorted(v for v in vals if v in halves)
    hit8 = sorted(v for v in vals if v in bytes_)
    print("[%2d] entries=%d  geom values (<=64): %s | in dwords:%s halves:%s bytes:%s" %
          (g["i"], g["n"], sorted(v for v in vals if v <= 64)[:24],
           hit32 or "-", hit16 or "-", hit8 or "-"))

print()
print("--- simple folds vs #2 / #4[0] ---")
for g in geo:
    folds = {
        "sum(kl+vl)": sum(g["kl"]) + sum(g["vl"]),
        "xor kl": __import__("functools").reduce(lambda a, b: a ^ b, g["kl"], 0),
        "xor vl": __import__("functools").reduce(lambda a, b: a ^ b, g["vl"], 0),
        "n": g["n"],
        "sum(kl)": g["sumK"],
        "sum(vl)": g["sumV"],
        "len(claims)": len(bytes.fromhex(S[g["i"]]["d10"])),
    }
    m2 = [k for k, v in folds.items() if v == g["d2"]]
    m40 = [k for k, v in folds.items() if v == g["d4"][0]]
    print("[%2d] #2=%08x folds==#2:%s   #4[0]=%08x folds==#4[0]:%s" %
          (g["i"], g["d2"], m2 or "-", g["d4"][0], m40 or "-"))