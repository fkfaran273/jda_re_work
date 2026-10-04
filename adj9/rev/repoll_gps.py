"""repoll_gps.py — poll /attribution for an already-spent GAID, N times.
Costs no new GAID and fires no new click; read-only against the record.
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_funnel as RF
import adj9_full_chain as FC

RESULT = sys.argv[2] if len(sys.argv) > 2 else "mint_arm_c_result.json"
res = json.load(open(os.path.join(HERE, RESULT)))
gps, auid = res["gps"], res["auid"]
print("[repoll] %s gps=%s" % (RESULT, gps), flush=True)

PROFILE = json.load(open(os.path.join(HERE, "moto_g42_profile.json")))
FC.DEV = dict(PROFILE["DEV"])
FC.UA = PROFILE["UA"]
FC.OFF_MINUTES, FC.OFF_LABEL = PROFILE["OFF_MINUTES"], PROFILE["OFF_LABEL"]
FC.ADD_IDFA = False
FC.USE_PROXY = False

N = int(sys.argv[1]) if len(sys.argv) > 1 else 3
for i in range(N):
    st, body = FC.api_attribution(gps, auid, "pt-" + auid[:8])
    try:
        a = json.loads(body).get("attribution", {})
        print("[poll %d] %s token=%s network=%s installed_at=%s "
              "first_session=%s reattributed=%s"
              % (i + 1, st, a.get("tracker_token"), a.get("network"),
                 a.get("installed_at"), a.get("first_session_time"),
                 a.get("is_reattributed")), flush=True)
    except Exception:
        print("[poll %d] %s %s" % (i + 1, st, body[:300]), flush=True)
    if i + 1 < N:
        time.sleep(20)
