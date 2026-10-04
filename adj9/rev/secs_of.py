# secs_of.py - for each of the 14 region samples, recover the signing second from
# the blob header law and pair it with the region: (second, payload) -> region.
# If two samples share (second, payload) and their regions differ => per-call
# randomness CONFIRMED with zero new device work. If (second, payload) always
# agrees => the region is a pure function to extract.
import base64
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

DET = json.load(open(os.path.join(HERE, "det_full.json"), encoding="utf-8"))


def sec_of(hdr):
    now = int(time.time())
    for s in range(now - 700000, now + 120):
        if make_header(s) == hdr:
            return s
    return None


rows = []
for i, s in enumerate(DET):
    bl = base64.b64decode(s["blob"] + "=" * (-len(s["blob"]) % 4))
    rows.append({"i": i, "sec": sec_of(bl[:16]), "hdr": bl[:16].hex(),
                 "payload": s["payload"], "d0": s["d0"], "d2": s["d2"],
                 "d4": s["d4"], "created_at": s.get("created_at"),
                 "d10len": s.get("d10len")})
for r in rows:
    print("det[%d] sec=%s created_at=%s d10len=%s d2=%s d4=%s…"
          % (r["i"], r["sec"], r["created_at"], r["d10len"], r["d2"],
             r["d4"][:24] if isinstance(r["d4"], str) else r["d4"]))
print("\n=== same (second, payload) groups ===")
seen = {}
hits = 0
for r in rows:
    key = (r["sec"], r["payload"])
    if key in seen:
        hits += 1
        a = seen[key]
        print("det[%d] vs det[%d]: d0 same=%s d2 same=%s d4 same=%s"
              % (a["i"], r["i"], a["d0"] == r["d0"], a["d2"] == r["d2"],
                 a["d4"] == r["d4"]))
    else:
        seen[key] = r
print("same-(second,payload) pairs: %d" % hits)
json.dump([{k: (v if k != "payload" else v[:60] + "…") for k, v in r.items()}
           for r in rows], open(os.path.join(HERE, "secs_of.json"), "w"), indent=1)
print("saved rev/secs_of.json")