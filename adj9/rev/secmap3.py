"""secmap3.py - the FULL (map, second, region) matrix. For each of the 8 wh4
signings we now have (order, sec). Join each to its region row:
  - region rows: all_signings[10] keyed by d10-bytes (claims buffer). The d10
    buffer embeds created_at + android_uuid + gps_adid: decode created_at
    from d10 latin1 and match to sign_inputs order's created_at.
  - then: (A) same second+same map => same region? (B) same second, diff map?
All 8 secs are DISTINCT here, so law (A) needs als/det rows sharing a second
with a wh4 row: check det[0]/det[2] (created .678, same as nsign7's map?) and
als7/als9 (d10lens 360, same claims as nsign7?).
"""
import os
import json
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
D = json.load(open(os.path.join(HERE, "det_full.json"), encoding="utf-8"))
W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))

SECS = [1789240075, 1789240076, 1789240079, 1789240228,
        1789240229, 1789240340, 1789240341, 1789240512]

print("=== created_at per wh4 order vs per als/det d10 ===")
for i, si in enumerate(W["sign_inputs"]):
    m = si["order"]
    k = m.find("created_at\x01")
    print("wh4[%d] sec=%d created=%s d10len~%d"
          % (i, SECS[i], m[k + 11:k + 35] if k >= 0 else "?", len(m)))

print("\n=== als/det d10 decoded created_at ===")
for i, s in enumerate(A):
    raw = bytes.fromhex(s["d10"]).decode("latin1", errors="replace")
    m = re.search(r"20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z", raw)
    print("als%d d10len=%d created=%s d2=%s d4h=%s"
          % (i, len(bytes.fromhex(s["d10"])), m.group(0) if m else "?",
             s["d2"], s["d4"][:16]))
for i, s in enumerate(D):
    print("det%d created=%s d2=%s d4h=%s"
          % (i, s["created_at"], "%08x" % s["d2"]
             if isinstance(s["d2"], int) else s["d2"], s["d4"][:16]))
print("done")
