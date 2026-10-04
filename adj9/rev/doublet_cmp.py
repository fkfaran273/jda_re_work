# doublet_cmp.py - compare the two blobs inside pull_mints.json: invert each header
# to its signing second, then decide.
import base64
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

rows = json.load(open(os.path.join(HERE, "pull_mints.json"), encoding="utf-8"))
now = int(time.time())
for r in rows:
    blob = base64.b64decode(r["b64"])
    if len(blob) != 192:
        r.update(sec=None, note="blob len %d" % len(blob))
        continue
    sec = None
    for s in range(now - 3600, now + 120):
        if make_header(s) == blob[:16]:
            sec = s
            break
    r.update(sec=sec, hdr=blob[:16].hex(), body=blob[16:].hex(), len=len(blob))
for r in rows:
    print("%s %dB stamp=%s second=%s header=%s"
          % (r["file"], r.get("len"), r.get("stamp"), r.get("sec"),
             r.get("hdr", "")[:16]))
print("\nmap identical: %s" % (rows[0]["map"] == rows[1]["map"]))
a, b = rows
print("second identical: %s (%s vs %s)" % (a.get("sec") == b.get("sec"),
                                           a.get("sec"), b.get("sec")))
print("body identical: %s" % (a.get("body") == b.get("body")))
if a.get("sec") == b.get("sec") and a.get("sec") is not None:
    print("\n=== VERDICT: same map + same second -> body identical=%s ==="
          % (a["body"] == b["body"]))
json.dump(rows, open(os.path.join(HERE, "pull_mints_rows.json"), "w"), indent=1)
print("saved rev/pull_mints_rows.json")