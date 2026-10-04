"""fixpairs.py - repair pair_h3 by inverting each blob header to its true second.

The header law inverts seconds uniquely (slice 102). For each pair_h3
row: recover the second from blob[:16] via make_header inversion over a
wide window, keep H/d0/d2/d4/blob as-is, rewrite second + mark fixed.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import make_header

P3 = json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))
print("rows: %d" % len(P3))

fixed = 0
for r in P3:
    want = bytes.fromhex(r["blob"][:32])
    if make_header(r["second"]) == want:
        print("pair i=%d d2=%s: second %d already correct" % (r["i"], r["d2"], r["second"]))
        continue
    # invert over +- 100000 s window around the claimed second
    hit = None
    for sec in range(r["second"] - 100000, r["second"] + 100001):
        if make_header(sec) == want:
            hit = sec
            break
    if hit is None:
        print("pair i=%d d2=%s: NO second inverts the header!" % (r["i"], r["d2"]))
        continue
    print("pair i=%d d2=%s: %d -> %d (delta %+d)" % (r["i"], r["d2"], r["second"], hit, hit - r["second"]))
    r["second"] = hit
    # nsign_ts stays as captured (it may legitimately differ)
    fixed += 1

json.dump(P3, open(os.path.join(HERE, "pair_h3.json"), "w"), indent=1)
print()
print("FIXED: %d / %d rows; pair_h3.json rewritten" % (fixed, len(P3)))
