# -*- coding: utf-8 -*-
"""rearm2_session_join.py -- THE decisive experiment, v2.

What v1 (rearm_and_ask.py) got wrong: it fired the USER'S link
(app.adjust.com/1xgvk2dz, different tracker) and then only ASKED
attribution.  Per ADJ7_SERVER_LOGIC the attribution GET is a read-only
peek; it is the SESSION (first activity after a click) that runs the
waterfall and re-opens the install story.

v2 does the full deterministic-join story on the CAPTURE'S OWN TRACKER:

  1. GET  https://nirio.go.link/home?adj_t=1zpd0epy&adj_campaign=OPT_APST
          &adj_adgroup={sub2}&adj_click_id={click_id}&adj_gps_adid={sub3}
          &idfa=EB91D1AA-...&gps_adid=EB91D1AA-...&os_name=ios
     -- the EXACT tracker (1zpd0epy) the capture's Kwanko click booked
        under, with the capture's own IDFA as the unprefixed idfa join
        key.  The {sub2}/{click_id}/{sub3} macros are left UNFILLED
        literally -- that is what the real network click did (the booked
        adgroup in the capture response is the literal '{sub2}').
  2. wait REARM2_GAP s (default 65: click registration + attribution lag)
  3. POST /session   capture sid-38 map, fresh stamps, OUR signature
     -- this is the waterfall trigger
  4. GET  /attribution  capture sid-39 map, fresh stamps, OUR signature
     -- the verdict read

PASS  = verdict == ('24s38ts0', 'Kwanko_Optivads _DTS')  (capture's own)
good  = any non-Organic network (state-level pass, the adj9_ios rule)
fail  = Organic (row did not join)

REAL TRAFFIC on the oracle device identity.  Deliberate only:
    python rearm2_session_join.py --fire
"""
import datetime
import gzip
import json
import os
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
BY = {r["sid"]: r for r in RECS}
CAP_ATTR = BY["39"]
CAP_SESSION = BY["38"]

IDFA = "EB91D1AA-B723-4291-AB2F-6F3E03751006"     # capture device
IDFV = "5C3E6785-B2DF-4992-A3EB-3816193CC01E"
CLIENT_SDK = next(v for k, v in CAP_ATTR["request_headers"]
                  if k.lower() == "client-sdk")
UA = next(v for k, v in CAP_ATTR["request_headers"]
          if k.lower() == "user-agent")
CAP_ADID = json.loads(CAP_SESSION["response"])["adid"]
CAP_J = json.loads(CAP_ATTR["response"])["attribution"]
CAP_VERDICT = (CAP_J.get("tracker_token"), CAP_J.get("network"))
CAP_TRACKER = CAP_J.get("tracker_token")

# the capture's own go.link tracker (from the booked attribution deeplink)
GO_LINK = ("https://nirio.go.link/home"
           "?adj_t=1zpd0epy"
           "&adj_campaign=OPT_APST"
           "&adj_adgroup={sub2}"
           "&adj_click_id={click_id}"
           "&adj_gps_adid={sub3}"
           "&idfa=" + IDFA +
           "&gps_adid=" + IDFA +
           "&os_name=ios")

S = _rq.Session()
S.headers.update({"User-Agent": UA, "Client-Sdk": CLIENT_SDK,
                  "Accept-Encoding": "gzip", "Accept": "*/*",
                  "Accept-Language": "en-US,en;q=0.9"})


def stamp(sec):
    dt = datetime.datetime.fromtimestamp(sec + 5 * 3600 + 30 * 60,
                                         datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0530" % (
        dt.microsecond // 1000)


def fire_click():
    url = GO_LINK
    click_sec = None
    try:
        from curl_cffi import requests as cr
        r = cr.get(url, timeout=30, impersonate="safari17_0",
                   allow_redirects=False)
        status, hdrs = r.status_code, r.headers
    except ImportError:
        r = S.get(url, timeout=30, allow_redirects=False)
        status, hdrs = r.status_code, r.headers
    d = hdrs.get("date") or hdrs.get("Date")
    if d:
        import email.utils
        try:
            click_sec = int(email.utils.parsedate_to_datetime(d).timestamp())
        except Exception:
            pass
    loc = hdrs.get("location") or "-"
    print(f"[click] HTTP {status}  Date-second={click_sec}")
    print("   loc:", loc[:120])
    return click_sec, loc


def send(label, rec, kind, second):
    fields = dict(rec["body"]) if isinstance(rec["body"], dict) else {}
    if "url" in rec and "?" in rec["url"] and not fields:
        q = rec["url"].split("?", 1)[1]
        fields = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
    fields["created_at"] = stamp(second)
    fields["sent_at"] = stamp(second + 1)
    auth, blob = sg.sign_request(fields, kind, second=second,
                                 client_sdk=CLIENT_SDK)
    if rec["method"] == "POST":
        r = S.post(rec["url"], data=fields,
                   headers={"Authorization": auth,
                            "Content-Type":
                            "application/x-www-form-urlencoded"},
                   timeout=30)
    else:
        r = S.get(rec["url"], params=fields,
                  headers={"Authorization": auth}, timeout=30)
    body = r.text
    if r.headers.get("content-encoding") == "gzip":
        try:
            body = gzip.decompress(r.content).decode("utf-8", "replace")
        except Exception:
            pass
    print(f"[{label}] HTTP {r.status_code}  sig={blob.hex().upper()[:16]}..")
    print("   ", body[:240].replace("\n", " "))
    return body


def main():
    if "--fire" not in sys.argv:
        print(__doc__)
        print("\n(would fire:", GO_LINK, ")")
        return 0
    print("oracle device:", IDFA, " idfv:", IDFV)
    print("tracker      :", CAP_TRACKER, " capture verdict:", CAP_VERDICT)
    print()

    fresh_reopen = bool(os.environ.get("REARM2_FRESH_DEDUPE"))
    if fresh_reopen:
        click_sec, loc = None, "(skipped -- click already armed)"
        print("(fresh-reopen mode: click already armed, skipping)")
    else:
        click_sec, loc = fire_click()
    gap = int(os.environ.get("REARM2_GAP", "65"))
    print(f"waiting {gap}s (click registration + attribution lag)...")
    time.sleep(gap)

    # 3. the waterfall trigger -- a signed session on the capture's map
    sec = int(time.time()) - 2
    sbody = send("session", CAP_SESSION, "session", sec)
    if fresh_reopen:
        # a genuine RE-OPEN: new dedupe token, session_count 2, fresh
        # started_at -- otherwise the capture's original-install dedupe
        # token makes the server treat this as a duplicate of Sept-8
        import uuid
        f = dict(CAP_SESSION["body"])
        f["primary_dedupe_token"] = str(uuid.uuid4())
        f["session_count"] = "2"
        f["subsession_count"] = "1"
        f["session_length"] = "27"
        f["time_spent"] = "27"
        f["started_at"] = stamp(sec - 27)
        rec2 = dict(CAP_SESSION)
        rec2["body"] = f
        sec = int(time.time()) - 2
        sbody = send("re-open session", rec2, "session", sec)
    try:
        adid = json.loads(sbody).get("adid")
    except ValueError:
        adid = None
    print(f"    session adid={adid}  == capture: {adid == CAP_ADID}")
    if fresh_reopen:
        time.sleep(8)   # attribution re-evaluation lag after re-open

    # 4. the verdict read
    sec2 = int(time.time()) - 2
    abody = send("attribution", CAP_ATTR, "attribution", sec2)
    verdict = None
    try:
        a = json.loads(abody).get("attribution", {})
        verdict = (a.get("tracker_token"), a.get("network"))
    except ValueError:
        pass
    if verdict and verdict[1] == "Organic":
        time.sleep(30)
        sec3 = int(time.time()) - 2
        abody = send("poll +30s", CAP_ATTR, "attribution", sec3)
        try:
            a = json.loads(abody).get("attribution", {})
            verdict = (a.get("tracker_token"), a.get("network"))
        except ValueError:
            pass

    print()
    print("=================== USER RULE CHECK ===================")
    print("  signature layer   :",
          "ACCEPTED" if verdict else "FAILED (no attribution object)")
    print("  capture verdict   :", CAP_VERDICT)
    print("  our verdict       :", verdict)
    if verdict is None:
        print("  >>> ERROR -- ask did not resolve")
    elif verdict == CAP_VERDICT:
        print("  >>> FULL PASS -- same tracker, same network,")
        print("      OUR signature making")
    elif verdict[1] != "Organic":
        print("  >>> STATE PASS -- non-organic with our signature")
    else:
        print("  >>> still Organic -- row did not join; next:")
        print("      fresh-IDFA full funnel (run_install_ios.py --live)")
    json.dump({"idfa": IDFA, "click_sec": click_sec, "loc": loc,
               "session_adid": adid, "verdict": verdict},
              open(os.path.join(HERE, "rearm2_result.json"), "w"), indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
