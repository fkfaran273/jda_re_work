# -*- coding: utf-8 -*-
"""bubble_android_recheck.py -- patient ARM re-read of the Android BubbleBus row.

The Android click MATCHED (302 with adjust_reftag + utm_campaign=AH), but the
funnel stopped asking after 3 quick polls and saw Organic.  Re-ask that same
row patiently: a signed session first (to arm ask_in), then attribution every
~15 s for a few minutes.
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_bubble_android as A

rec = json.load(open(os.path.join(HERE, "last_run_bubble_android.json")))
gaid = rec["gaid"]
auuid = rec["android_uuid"]
click_second = rec["click_second"]
print("row:", json.dumps({k: rec[k] for k in
                          ("app", "gaid", "adid", "click_second")}, indent=1))

# re-arm: signed session so the backend hands back ask_in
sec = A.signing_second()
sf = A.build_session(gaid, auuid, sec, click_second)
st, body = A.call("POST", "/session", sf, A.sign(sf, "session", sec))
print("re-arm session -> %s %s" % (st, body[:120]), flush=True)
try:
    ask_in = json.loads(body).get("ask_in")
except ValueError:
    ask_in = None
print("ask_in:", ask_in, flush=True)

verdict = {}
for i in range(10):
    time.sleep(15 if i else 3)
    asec = A.signing_second()
    af = A.build_attr(gaid, auuid, asec)
    _s, b = A.call("GET", "/attribution", af, A.sign(af, "attribution", asec))
    try:
        p = json.loads(b)
    except ValueError:
        print("poll %d -> unparsable %s" % (i + 1, b[:100]))
        continue
    verdict = p.get("attribution") or {}
    print("poll %-2d -> %-10s / %-9s ask_in=%s  %s"
          % (i + 1, verdict.get("network"), verdict.get("tracker_token"),
             p.get("ask_in"), verdict.get("tracker_name")), flush=True)
    if verdict.get("network") and verdict["network"] != "Organic":
        print()
        print("*** IT JOINED (late) ***")
        print(json.dumps(verdict, indent=1))
        break

print()
print("FINAL:", json.dumps(verdict))