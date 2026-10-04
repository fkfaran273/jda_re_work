"""find_pair_blobs.py - from wh_blobs2.json, find blobs signed at sec 1789240512
(the same claims+second as desc_det rows 0/2). Match them to d2 via the header
inversion + d2 carried in the EMIT plane? No - simpler: invert each candidate's
header to its second; keep sec==1789240512 ones, then FinEx each against the two
distinct descriptor sets. BYTE-EXACT = the blob belongs to that region.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header

ORDER = json.load(open(os.path.join(HERE, "adj9_material.json")))["va_order"]
CONST8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
CONST9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")

pool = json.load(open(os.path.join(HERE, "wh_blobs2.json"), encoding="utf-8"))
blobs = pool["auth"]
print("pool blobs: %d" % len(blobs))

# invert each to its second (use ts as the seed)
cands = {}
for hx, recs in blobs.items():
    tss = [t for _, t in recs]
    base = tss[0] // 1000 if tss else 0
    want = bytes.fromhex(hx[:32])
    sec = None
    for delta in range(0, 5):
        for s in ((base + delta, base - delta) if delta else (base,)):
            if make_header(s) == want:
                sec = s
                break
        if sec:
            break
    if sec:
        cands.setdefault(sec, []).append(hx)

secs = sorted(cands)
print("seconds covered: %d (%d..%d)" % (len(secs), secs[0], secs[-1]))
print("blobs at 1789240512:", len(cands.get(1789240512, [])))
for hx in cands.get(1789240512, []):
    print("  ", hx[:64])
json.dump({str(s): hs for s, hs in cands.items()},
          open(os.path.join(HERE, "blob_by_sec.json"), "w"), indent=0)
