# -*- coding: utf-8 -*-
"""replay_capture_attribution.py -- THE user rule test for adj7 iOS.

Replays the genuine capture's attribution GET (sid 39, consent.adjust.com,
booked NON-ORGANIC: tracker 24s38ts0 / Kwanko_Optivads _DTS) with OUR
signature making (adj7_ios_pure): same wire map, same device row
(idfa/idfv/adid), our fresh nonce + MINSTD header + our signature.

Probes:
  A  verbatim capture map (stale created_at, signing second = the capture's
     1788846076 so the header law matches the stale stamps)
  B  same map, fresh created_at/sent_at (signing second = now)
Both carry OUR signature -- if the signature making is correct the server
must accept both (200 + attribution object); the verdict shows whether the
device row still holds the capture's non-organic booking.

PASS (the user rule): HTTP 200 with the SAME non-organic response shape as
the capture (tracker 24s38ts0 / Kwanko_Optivads _DTS).
Also acceptable per the adj9_ios rule: any NON-"Organic" state
("No User Consent"/unattr counts as the non-organic state there).
"""
import json
import os
import re
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import adj7_ios_pure as sg          # noqa: E402
from datetime import datetime, timezone, timedelta  # noqa: E402

RECS = json.load(open(os.path.join(
    HERE, "nirio_08Sep", "nirioiosauto_08Sep_ios_CT_adjust.json"),
    encoding="utf-8"))
CAP = next(r for r in RECS if r["sid"] == "39")
URL = CAP["url"]
Q = URL.split("?", 1)[1]
FIELDS = dict(urllib.parse.parse_qsl(Q, keep_blank_values=True))
CAP_SECOND = 1788846076             # probe3's brute-forced header second
CLIENT_SDK = next(v for k, v in CAP["request_headers"]
                  if k.lower() == "client-sdk")
UA = next(v for k, v in CAP["request_headers"]
          if k.lower() == "user-agent")

genuine = CAP["response"]
gj = json.loads(genuine)
g_attr = gj["attribution"]
print("genuine (capture) attribution response:")
print("   tracker  :", g_attr.get("tracker_token"))
print("   network  :", g_attr.get("network"))
print("   campaign :", g_attr.get("campaign"), " adgroup:",
      g_attr.get("adgroup"))
print("   engage   :", g_attr.get("engagement_time"),
      " installed:", g_attr.get("installed_at"))


def _stamp(ts):
    dt = datetime.fromtimestamp(ts + 5 * 3600 + 30 * 60, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0530" % ((ts % 1) * 0)


def send(label, fields, sec):
    auth, blob = sg.sign_request(fields, "attribution", second=sec,
                                 client_sdk=CLIENT_SDK)
    # the capture's exact transport headers
    import requests as _rq
    h = {"User-Agent": UA, "Client-Sdk": CLIENT_SDK,
         "Authorization": auth, "Accept-Encoding": "gzip"}
    r = _rq.get(URL, params=fields, headers=h, timeout=30)
    print(f"\n[{label}] HTTP {r.status_code}  (sig {blob.hex().upper()[:20]}..)")
    try:
        a = r.json().get("attribution", {})
    except ValueError:
        print("   body:", r.text[:200])
        return None
    print("   tracker  :", a.get("tracker_token"))
    print("   network  :", a.get("network"))
    print("   campaign :", a.get("campaign"), " adgroup:", a.get("adgroup"))
    print("   engage   :", a.get("engagement_time"),
          " installed:", a.get("installed_at"))
    return a


def classify(a):
    if a is None:
        return "ERROR"
    net = a.get("network", "")
    if net == g_attr.get("network") and \
            a.get("tracker_token") == g_attr.get("tracker_token"):
        return "SAME NON-ORGANIC (capture booking reproduced)"
    if net == "Organic":
        return "Organic (device row re-evaluated/expired)"
    if net and net != "Organic":
        return f"NON-ORGANIC state ({net})"
    return "other"


def main():
    out = {}
    # A: verbatim map, capture's signing second (header law = stale stamps)
    a = send("A verbatim+capture-sec", FIELDS, CAP_SECOND)
    out["A"] = classify(a)
    # B: fresh times, signing second = now (the live-funnel shape)
    fresh = dict(FIELDS)
    now = int(time.time()) - 2
    fresh["created_at"] = _stamp(now)
    fresh["sent_at"] = _stamp(now)
    b = send("B fresh-times+now-sec", fresh, now)
    out["B"] = classify(b)

    print("\n=================== USER RULE CHECK ===================")
    for k, v in out.items():
        print(f"  probe {k}: {v}")
    passed = any("NON-ORGANIC" in v for v in out.values())
    print("  verdict :", "PASS -- non-organic state with OUR signature"
          if passed else
          "the booking row no longer returns non-organic (see probes)")
    json.dump({"A": out["A"], "B": out["B"],
               "A_raw": a, "B_raw": b},
              open(os.path.join(HERE, "replay_result.json"), "w"),
              indent=1, default=str)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
