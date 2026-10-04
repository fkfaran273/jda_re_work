"""doublet2.py - RE-verify the slice-116 doublet from the FRESHLY pulled files,
plus test the alternative: do the two blobs' headers invert to the SAME second
via the header law (the claim), and do their mapPairs differ in ANY key
(dismissing the 'same map' premise)?
"""
import os
import json
import base64
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

A = json.load(open(os.path.join(HERE, "dev_p1.json"), encoding="utf-8"))
B = json.load(open(os.path.join(HERE, "dev_p2.json"), encoding="utf-8"))
ba = base64.b64decode(A["blobB64"])
bb = base64.b64decode(B["blobB64"])
print("len:", len(ba), len(bb))
print("head:", ba[:16].hex())
print("body_eq:", ba[16:] == bb[16:])
ma = {k: v for k, v in A["mapPairs"]}
mb = {k: v for k, v in B["mapPairs"]}
print("map keys:", len(ma), len(mb), "equal:", ma == mb)
for k in sorted(set(ma) | set(mb)):
    if ma.get(k) != mb.get(k):
        print("  DIFF", k, repr(ma.get(k)), repr(mb.get(k)))
# invert header: search around the stamp
import datetime
st = A.get("stamp", "")
print("stamp:", st)
try:
    dt = datetime.datetime.strptime(st[:24], "%Y-%m-%dT%H:%M:%S.%f")
    hint = int(dt.replace(tzinfo=datetime.timezone.utc).timestamp())
except Exception as e:
    hint = 1789813690
    print("stamp parse fail:", e)
for s in range(hint - 7200 - 19800 - 100, hint + 7200):
    if make_header(s) == ba[:16]:
        print("header inverts to second:", s)
        break
else:
    print("header inversion FAILED in window")
print("done")
