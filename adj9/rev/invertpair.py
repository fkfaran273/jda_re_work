"""invertpair.py - invert ONE pair_h3 blob header at a time.

Usage: python invertpair.py <idx>
Writes the fixed second into pair_h3.json for that row only.
Each run takes ~30-60 s (one FinEx-free header inversion over a
+-100000 s window; make_header is ~7000/s).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import make_header

idx = int(sys.argv[1])
P3 = json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))
r = [x for x in P3 if x["i"] == idx][0]
want = bytes.fromhex(r["blob"][:32])
if make_header(r["second"]) == want:
    print("pair i=%d already correct (%d)" % (idx, r["second"]), flush=True)
    sys.exit(0)
base = r["second"]
for delta in range(0, 100001):
    for sec in (base + delta, base - delta) if delta else (base,):
        if make_header(sec) == want:
            print("pair i=%d FIXED: %d -> %d (delta %+d)" % (idx, base, sec, sec - base), flush=True)
            r["second"] = sec
            json.dump(P3, open(os.path.join(HERE, "pair_h3.json"), "w"), indent=1)
            print("saved", flush=True)
            sys.exit(0)
    if delta % 10000 == 0:
        print("  ...delta %d" % delta, flush=True)
print("pair i=%d: NO second inverts the header!" % idx, flush=True)
sys.exit(1)
