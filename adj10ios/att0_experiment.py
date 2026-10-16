# -*- coding: utf-8 -*-
"""att0_experiment.py -- the att_status=0 armed path on the lululemon row.

Question (user): if we also send a session, set att_status=0 -- what does
the attribution answer then?  (The row is a consented att=3 device whose
booked admatic click aged out; att=0 is the watsons-style no-consent
shape whose stable answer was reproduced byte-exact.)

Probes (all signed by adj7ios_pure, headers_id 8 / native 3.62.0):
  S0   POST /session, capture params but att_status=0   (retry through
       the 20-min per-adid session cadence)
  A1   armed GET /attribution, att_status=0, idfa kept
  A2   GET /attribution, att_status=0, idfa dropped (true no-consent shape)
"""
import json
import re
import sys
import time

import requests

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7ios")
import adj7ios_pure as sg                                   # noqa: E402
from replay_lululemon import HOST, SDK, hdrs, load          # noqa: E402

OUT = r"C:\Users\Apps\Downloads\com.penti.app\adj7ios\att0_result.json"


def jget(r):
    try:
        return r.json()
    except ValueError:
        return {}


def main():
    reqs = load()
    ses, atr = reqs["session"]["params"], reqs["attribution"]["params"]
    out = {}

    ses0 = dict(ses)
    ses0["att_status"] = "0"
    a0 = dict(atr)
    a0["att_status"] = "0"
    a0_noidfa = {k: v for k, v in a0.items() if k != "idfa"}

    # S0 -- session with att_status=0 (retry through the rate-limit)
    for attempt in range(30):
        auth_s, _ = sg.sign_request(ses0, "session", client_sdk=SDK)
        h = hdrs(auth_s)
        h["Content-Type"] = "application/x-www-form-urlencoded"
        r = requests.post(HOST + "/session", data=ses0, headers=h,
                          timeout=30)
        j = jget(r)
        print("[S0 try %d] HTTP %s %s"
              % (attempt + 1, r.status_code,
                 json.dumps(j)[:180]), flush=True)
        if r.status_code == 200:
            break
        if "check interval" in json.dumps(j) or "too frequent" \
                in json.dumps(j):
            print("     rate-limited; sleeping 60 s", flush=True)
            time.sleep(60)
            continue
        break
    out["S0_session_att0"] = {"http": r.status_code, "json": j}

    ask = j.get("ask_in") if r.status_code == 200 else None
    if ask:
        time.sleep(ask / 1000.0 + 2)

    for label, mp in (("A1 armed att0 +idfa", a0),
                      ("A2 att0 no idfa", a0_noidfa)):
        auth, _ = sg.sign_request(mp, "attribution", client_sdk=SDK)
        r = requests.get(HOST + "/attribution", params=mp,
                         headers=hdrs(auth), timeout=30)
        j = jget(r)
        a = j.get("attribution") or {}
        print("\n[%s] HTTP %s adid=%s" % (label, r.status_code, j.get("adid")),
              flush=True)
        print("   tracker=%s name=%s network=%s engage=%s installed=%s"
              % (a.get("tracker_token"), a.get("tracker_name"),
                 a.get("network"), a.get("engagement_time"),
                 a.get("installed_at")), flush=True)
        out[label] = {"http": r.status_code, "json": j}
        time.sleep(3)

    with open(OUT, "w") as f:
        json.dump(out, f, indent=1)
    print("\nwritten:", OUT, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
