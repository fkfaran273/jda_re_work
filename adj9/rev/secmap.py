"""secmap.py - recover the signing second of every region sample, then test the
two candidate laws:
  (A) region = f(second) only  -> same second => same region (any map)
  (B) region = f(map, second)  -> same (map, second) => same region

Seconds come from the blob header law: header == Random3(second). For als[*]
we have no stored blob... but wh4_records.nsigns[8] ARE the device blobs and
sign_inputs[8] are their maps. Pair them: the golden pair is idx 7. For the
other 7, we need (map -> region): all_signings[*].d10 == sign_inputs[?].order?
#10 bytes decode: d10 hex starts with b'lcAG...'?? Check: d10[0] bytes are the
claims buffer; the sign_input order uses \x01\x02 separators. Try: does
bytes.fromhex(d10) contain the created_at / gps_adid substrings of a
sign_input order? That joins region rows to (map, second) rows.
"""
import os
import json
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))

print("=== join: all_signings d10 vs wh4 sign_input orders ===")
for i, s in enumerate(A):
    raw = bytes.fromhex(s["d10"])
    best = None
    for j, si in enumerate(W["sign_inputs"]):
        o = si["order"].encode("latin1", errors="ignore")
        # the claims buffer should embed several long values; test 3 anchors
        anchors = [a for a in (b"f476b3d4", b"jut9tib0eeps", b"com.penti.app")
                   if a in raw]
        oa = [a for a in anchors if a in o]
        if anchors and len(oa) == len(anchors):
            best = (j, len(oa))
    print("als%d d10len=%d anchors=%s" % (i, len(raw), best))
print("done")
