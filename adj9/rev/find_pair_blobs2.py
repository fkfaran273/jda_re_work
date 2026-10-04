"""find_pair_blobs2.py - the nsign-half of wh_blobs2.json (records whose hex was
192 B). Same-second-pair entry 2's blob may live there with its own timestamp.
For each blob with ts near 1789240512+/-10s, invert to its true second.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

pool = json.load(open(os.path.join(HERE, "wh_blobs2.json"), encoding="utf-8"))
ns = pool["nsign"]
print("nsign blobs: %d" % len(ns))

win = [t for _, ts in sum((v for v in ns.values()), []) if True]
near = {}
for hx, recs in ns.items():
    for log, ts in recs:
        if abs(ts // 1000 - 1789240512) <= 30:
            # invert using the ts seed
            want = bytes.fromhex(hx[:32])
            sec = None
            for delta in range(0, 8):
                for s in ((ts // 1000 + delta, ts // 1000 - delta) if delta else (ts // 1000,)):
                    if make_header(s) == want:
                        sec = s
                        break
                if sec:
                    break
            near.setdefault((log, ts, sec), []).append(hx[:16])

for k in sorted(near, key=lambda x: x[1]):
    print("  %s ts=%d sec=%s -> %s" % (k[0], k[1], k[2], near[k]))
