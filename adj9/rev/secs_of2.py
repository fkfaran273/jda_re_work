# secs_of2.py - same question, built from what det_full.json ACTUALLY holds:
# payload + per-sample region + created_at. Recover the signing second from the
# DEVICE LOG (wh4) instead: pair each sample's created_at with the nsign record
# whose header-second sits at that wall time (same pairing desc_det used).
import calendar
import datetime
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
DET = json.load(open(os.path.join(HERE, "det_full.json"), encoding="utf-8"))

raw = open(os.path.join(DEV, "adj9_wh4.log"), "rb").read().decode(
    "utf-8", errors="replace")
recs = re.findall(r"###ADJ9_BEGIN type=nsign utf8len=\d+ ts=(\d+)\n"
                  r"text: len=\d+\nnano_out=\d+\nhex=([0-9a-f]+)", raw)
print("device nsign records:", len(recs))
print("\n=== samples vs device signings ===")
for i, s in enumerate(DET):
    ca = s.get("created_at")
    print("det[%d] created_at=%s d10len=%s d2=%s d4=%s…"
          % (i, ca, s.get("d10len"), s.get("d2"),
             (s.get("d4") or "")[:20]))
json.dump({"nsign_ts": [int(t) for t, _ in recs],
           "note": "pair by created_at; no blob field in det_full.json"},
          open(os.path.join(HERE, "secs_of.json"), "w"), indent=1)
print("saved rev/secs_of.json")