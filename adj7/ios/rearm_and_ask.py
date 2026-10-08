# -*- coding: utf-8 -*-
"""rearm_and_ask.py -- THE decisive non-organic experiment.

Today's full replay proved: our signature opens the capture's device row
(session -> the EXACT capture adid), but the row answers Organic because its
engagement state aged out (tps: "device not found"; session: no ask_in).

Missing ingredient = a live click engagement on the row.  This script:
  1. fires the user's tracker link with the CAPTURE'S OWN IDFA
     (link: app.adjust.com/1xgvk2dz + idfa=EB91D1AA-... + click_id=niri_oracle...)
     -> Adjust registers a FRESH engagement for that device
  2. asks attribution with OUR signature making (map = capture sid 39,
     fresh times)
  3. verdict check:
       tracker 24s38ts0 / Kwanko_Optivads _DTS  -> FULL PASS
       any non-"Organic" network               -> NON-ORGANIC STATE (pass per
                                                  the adj9_ios rule)
       Organic                                 -> the row did not join
    (optional second ask +1.5 s and +30 s, the double-ask pattern)

NOTE: this sends REAL traffic on the capture's device identity (the
oracle device).  Run only deliberately: python rearm_and_ask.py --fire
```
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
import requests as _rq              # noqa: E402

RECS = json.load(open(os.path.join(
    HERE, "nirio_08Sep", "nirioiosauto_08Sep_ios_CT_adjust.json"),
    encoding="utf-8"))
CAP_ATTR = next(r for r in RECS if r["sid"] == "39")
CLIENT_SDK = next(v for k, v in CAP_ATTR["request_headers"]
                  if k.lower() == "client-sdk")
UA = next(v for k, v in CAP_ATTR["request_headers"]
          if k.lower() == "user-agent")

IDFA = "EB91D1AA-B723-4291-AB2F-6F3E03751006"     # the capture's device
CLICK_URL = ("https://app.adjust.com/1xgvk2dz"
             "?campaign=NIRIO_mobsuccess_iOS&adgroup=3710"
             "&creative=oracle_rearm&os_name=ios"
             "&click_id=oracle_{n}&idfa=" + IDFA)
S = _rq.Session()
S.headers.update({"User-Agent": UA, "Client-Sdk": CLIENT_SDK,
                  "Accept-Encoding": "gzip", "Accept": "*/*"})


def fire_click():
    url = CLICK_URL.format(n=str(int(time.time()))[-8:])
    import email.utils
    click_sec = None
    try:
        from curl_cffi import requests as cr
        r = cr.get(url, timeout=30, impersonate="safari17_0",
                   allow_redirects=False)
        status, hdrs, text = r.status_code, r.headers, r.text
    except ImportError:
        r = S.get(url, timeout=30, allow_redirects=False)
        status, hdrs, text = r.status_code, r.headers, r.text
    d = hdrs.get("date") or hdrs.get("Date") or hdrs.get("date".title())
    if d:
        try:
            click_sec = int(email.utils.parsedate_to_datetime(d).timestamp())
        except Exception:
            pass
    m = re.search(r"adjust_reftag=([A-Za-z0-9]+)",
                  hdrs.get("location", "") if hdrs.get("location") else text)
    print(f"[click] HTTP {status}  Date-second={click_sec}  "
          f"reftag={m.group(1) if m else None}")
    print("   conn:", (hdrs.get("connection") or "")[:60],
          "| loc:", (hdrs.get("location") or "-")[:100])
    return click_sec, (m.group(1) if m else None)


def stamp(sec):
    import datetime
    dt = datetime.datetime.fromtimestamp(sec + 5 * 3600 + 30 * 60,
                                         datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0530" % (
        dt.microsecond // 1000)


def ask(label, sec=None):
    sec = sec or int(time.time()) - 2
    # the capture's GET carries its device map in the URL QUERY (the
    # extractor leaves body empty for GETs) -- reuse it, with fresh times
    q = CAP_ATTR["url"].split("?", 1)[1]
    fields = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
    fields["created_at"] = stamp(sec)
    fields["sent_at"] = stamp(sec + 1)
    auth, blob = sg.sign_request(fields, "attribution", second=sec,
                                 client_sdk=CLIENT_SDK)
    r = S.get("https://consent.adjust.com/attribution", params=fields,
              headers={"Authorization": auth}, timeout=30)
    try:
        a = r.json().get("attribution", {})
        verdict = (a.get("tracker_token"), a.get("network"))
    except ValueError:
        verdict = None
        print("   body:", r.text[:200])
    print(f"[{label}] HTTP {r.status_code}  verdict={verdict}")
    return verdict


def main():
    if "--fire" not in sys.argv:
        print(__doc__)
        print("\n(would fire the click for idfa", IDFA, "now)")
        return 0
    print("oracle device:", IDFA)
    if os.environ.get("REARM_ASK_ONLY"):
        click_sec, reftag = None, None      # the click is already armed
        print("(ask-only: click already fired, skipping)")
    else:
        click_sec, reftag = fire_click()
        gap = int(os.environ.get("REARM_GAP", "30"))
        print(f"waiting {gap}s for the click to register...")
        time.sleep(gap)
    v = ask("ask#1")
    if v and v[1] == "Organic":
        time.sleep(1.5)
        v = ask("re-ask +1.5s", )
    if v and v[1] == "Organic":
        print("waiting 30s (attribution lag)...")
        time.sleep(30)
        v = ask("poll +30s")
    print()
    print("=================== USER RULE CHECK ===================")
    print("  capture non-organic : ('24s38ts0', 'Kwanko_Optivads _DTS')")
    print("  our verdict         :", v)
    if v is None:
        print("  >>> ERROR (device not resolved -- check the ask)")
    elif v[1] != "Organic":
        print("  >>> PASS -- non-organic state with OUR signature making;",
              "FULL" if v == ("24s38ts0", "Kwanko_Optivads _DTS")
              else "state-level", "match")
    else:
        print("  >>> the row did not join the fresh click")
    json.dump({"idfa": IDFA, "click_sec": click_sec, "reftag": reftag,
               "verdict": v},
              open(os.path.join(HERE, "rearm_result.json"), "w"), indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
