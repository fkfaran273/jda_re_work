import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

pool = json.load(open(os.path.join(HERE, "wh_blobs2.json"), encoding="utf-8"))
ns = pool["nsign"]
print("nsign blobs:", len(ns))

for hx, recs in ns.items():
    for log, ts in recs:
        if abs(ts // 1000 - 1789240512) <= 30:
            want = bytes.fromhex(hx[:32])
            sec = None
            for delta in range(0, 8):
                base = ts // 1000
                pair = (base,) if delta == 0 else (base + delta, base - delta)
                for s in pair:
                    if make_header(s) == want:
                        sec = s
                        break
                if sec is not None:
                    break
            print("  %s ts=%d sec=%s head=%s" % (log, ts, sec, hx[:32]))
