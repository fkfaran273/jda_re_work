# wh4_pairs.py - THE ground truth pairing: device adj9_wh4.log nsign blobs (with
# ts) against the golden EMIT descriptors. 8 nsign records; match each blob's
# header to a second, match each #10-created_at to a request time, then report
# which blob used which region: (second, payload) -> (d0,d2,d4).
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

DEV = os.path.join(os.path.dirname(HERE), "device")
DET = json.load(open(os.path.join(HERE, "det_full.json"), encoding="utf-8"))
raw = open(os.path.join(DEV, "adj9_wh4.log"), "rb").read().decode(
    "utf-8", errors="replace")
print("log bytes:", len(raw))
print("has ADJ9_BEGIN:", raw.count("###ADJ9_BEGIN"))
print("types:", sorted(set(re.findall(r"type=(\w+)", raw)))[:30])
recs = re.findall(r"ts=(\d+)[^#]*?hex=([0-9a-f]{384})", raw)
print("nsign-shaped blob records:", len(recs))
for ts, hx in recs:
    sec = None
    t = int(ts) // 1000
    for s in range(t - 60, t + 60):
        if make_header(s) == bytes.fromhex(hx[:32]):
            sec = s
            break
    print("ts=%s second=%s hdr=%s" % (ts, sec, hx[:32]))
json.dump({"ts": [t for t, _ in recs]}, open(os.path.join(HERE, "wh4_pairs.json"),
                                             "w"), indent=1)
print("saved rev/wh4_pairs.json")