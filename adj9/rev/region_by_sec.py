"""region_by_sec.py - is the region a function of the SIGNING SECOND (a PRNG seeded
by time), independent of the map?

Logic: the region is deterministic for the same (map, second) (slice 116) and is
not a ROM constant nor a keyed/unkeyed hash of the map or of H (const_scan,
region_derive, region_fit). The remaining simple model is a per-call PRNG seeded
by time. Test: group every region sample we own by its signing second (recovered
from the blob header when we have the blob) and look for:
    * same second, DIFFERENT map  -> different region?  => map enters too
    * same second, DIFFERENT map  -> same region?       => region = f(second) only
"""
import base64
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))
DET = json.load(open(os.path.join(HERE, "det_full.json"), encoding="utf-8"))

try:
    ALS = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
except Exception as e:
    ALS = []
    print("all_signings: %s" % e)

print("als fields: %s" % (sorted(ALS[0].keys()) if ALS else "-"))
print("wh4 keys: %s" % sorted(W.keys()))

# 1) device blobs -> their own second, plus the sign_input map paired by created_at
raw = open(os.path.join(os.path.dirname(HERE), "device", "adj9_wh4.log"),
           "rb").read().decode("utf-8", errors="replace")
import re
ns = re.findall(r"###ADJ9_BEGIN type=nsign utf8len=\d+ ts=(\d+)\n"
                r"text: len=\d+\nnano_out=\d+\nhex=([0-9a-f]+)", raw)
print("device nsign blobs: %d" % len(ns))
seen = {}
for ts, hx in ns:
    blob = bytes.fromhex(hx)
    sec = None
    t = int(ts) // 1000
    for s in range(t - 60, t + 60):
        if make_header(s) == blob[:16]:
            sec = s
            break
    seen.setdefault(sec, []).append((int(ts), hx[:32]))
print("\n=== device blobs grouped by recovered second ===")
for sec in sorted(k for k in seen if k):
    rows = seen[sec]
    print("  sec=%s : %d blob(s)  %s" % (sec, len(rows),
                                         ", ".join(h for _, h in rows)))
dup = [s for s, r in seen.items() if s and len({h for _, h in r}) == 1 and len(r) > 1]
print("  seconds with a repeated (identical) blob: %s" % dup)

# 2) region samples we know, with their own seconds where available
print("\n=== region samples ===")
for i, s in enumerate(DET):
    print("  det[%d] created_at=%s d2=%s d4=%s"
          % (i, s.get("created_at"), s.get("d2"), (s.get("d4") or "")[:24]))
secs = {}
for i, s in enumerate(ALS):
    if s.get("d4"):
        key = (s.get("sec"), s.get("created_at"))
        secs.setdefault(key, []).append((i, s["d4"]))
print("\n=== als grouped by (sec, created_at) ===")
for key, rows in sorted(secs.items(), key=lambda kv: str(kv[0])):
    same = len({d4 for _, d4 in rows}) == 1
    print("  %s : n=%d identical d4=%s" % (key, len(rows), same))
print("done")