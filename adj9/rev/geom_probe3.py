"""geom_probe3.py - claim-LAYOUT test on the 10 real signings.

#10 is a separator-less concatenation of claim values in the law's key order, so the
layout (offsets/lengths of the recognisable fields) is measurable directly from the
string with anchored regexes.  This computes those anchors and tests them against the
region (#0's W0 + tile, #2, #4's 8 words) as dwords / 16-bit halves / bytes / folds.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))

ISO = re.compile(rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z[+-]\d{4}")
UUID = re.compile(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
VER = re.compile(rb"\d+\.\d+\.\d+")


def be(hexs, n):
    raw = bytes.fromhex(hexs)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 4 * n, 4)]


rows = []
for i, x in enumerate(S):
    b = bytes.fromhex(x["d10"])
    uu = list(UUID.finditer(b))
    iso = ISO.search(b)
    ver = VER.search(b)
    g = {
        "len": len(b),
        "tok": 28,
        "uuid1_off": uu[0].start() if uu else None,
        "uuid2_off": uu[1].start() if len(uu) > 1 else None,
        "n_uuid": len(uu),
        "iso_off": iso.start() if iso else None,
        "iso_end": iso.end() if iso else None,
        "ver_off": ver.start() if ver else None,
        "ver_len": (ver.end() - ver.start()) if ver else None,
        "pre_iso": iso.start() if iso else None,
        "after_iso": (len(b) - iso.end()) if iso else None,
    }
    d0 = be(x["d0"], 5)
    rows.append({"i": i, "g": g, "W0": d0[0], "tile": d0[1:5],
                 "d2": int(x["d2"], 16), "d4": be(x["d4"], 8)})

print("%-3s %-5s %-9s %-9s %-5s %-9s %-9s %-9s %s" %
      ("i", "len", "uuid1", "uuid2", "nU", "iso_off", "ver_off", "afterIso", "#2"))
for r in rows:
    g = r["g"]
    print("%-3d %-5d %-9s %-9s %-5d %-9s %-9s %-9s %08x" %
          (r["i"], g["len"], g["uuid1_off"], g["uuid2_off"], g["n_uuid"],
           g["iso_off"], g["ver_off"], g["after_iso"], r["d2"]))

print()
print("--- membership of layout numbers in the unknowns (per sample) ---")
tot = 0
for r in rows:
    g = r["g"]
    nums = set(v for k, v in g.items() if isinstance(v, int))
    U = [("W0", r["W0"])] + [("tile%d" % k, t) for k, t in enumerate(r["tile"])] + \
        [("#2", r["d2"])] + [("#4[%d]" % k, w) for k, w in enumerate(r["d4"])]
    hits = []
    for nm, w in U:
        if w in nums:
            hits.append("%s==%08x(dword)" % (nm, w))
        for sh, lbl in ((16, "hi16"), (0, "lo16")):
            if ((w >> sh) & 0xFFFF) in nums:
                hits.append("%s.%s==%d" % (nm, lbl, (w >> sh) & 0xFFFF))
        for sh in (0, 8, 16, 24):
            if ((w >> sh) & 0xFF) in nums:
                hits.append("%s.byte%d==%d" % (nm, sh // 8, (w >> sh) & 0xFF))
    tot += len(hits)
    print("[%2d] %s" % (r["i"], hits if hits else "none"))

print()
print("total layout hits across samples: %d" % tot)
print()
print("--- #4 as bit-fields: set-bit positions vs layout numbers ---")
for r in rows:
    nums = set(v for k, v in r["g"].items() if isinstance(v, int))
    for k, w in enumerate(r["d4"]):
        bits = [i for i in range(32) if (w >> i) & 1]
        hit = [i for i in bits if i in nums]
        if hit:
            print("[%2d] #4[%d]=%08x bits=%s layout-hits=%s" %
                  (r["i"], k, w, bits[:12], hit))
print("(no output above = no bit position matches a layout number)")