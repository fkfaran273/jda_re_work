"""checkpairs.py - do the pair_h3 seconds match their blob headers?

Fast offline check (no FinEx): for each pair_h3 row, compare
make_header(second) against blob[:16]. If they differ, the assigned
second is wrong and every downstream FinEx arm was doomed.
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
bad = 0
for r in P3:
    want = bytes.fromhex(r["blob"][:32])
    got = make_header(r["second"])
    ok = got == want
    if not ok:
        bad += 1
    print("pair i=%-2d d2=%-8s sec=%-11d hdr_match=%s blob=%s calc=%s" %
          (r["i"], r["d2"], r["second"], ok, r["blob"][:16],
           got.hex()[:16] if got else "-"))
print()
print("MISMATCHED: %d / %d" % (bad, len(P3)))
