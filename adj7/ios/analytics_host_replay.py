# -*- coding: utf-8 -*-
"""analytics_host_replay.py -- ONE test: replay the capture's sid-39
attribution GET on analytics.adjust.com (att_status=0 host) with OUR nirio
adj7 signature maker, using the capture's exact device identity.
adj9_ios used this host for its No User Consent proof (penti, adj9).
Question: does nirio adj7 analytics host return the SAME booked Kwanko
(proving host is irrelevant / Organic was consent-host-specific), OR return
Organic here too (proving analytics-host behavior is app-specific: nirio
returns Organic even when signature is accepted)?
"""
import json, os, sys, time, urllib.parse
import requests as _rq
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE:=".", ".."))
import adj7_ios_pure as sg

RECS = json.load(open(os.path.join(
    "nirio_08Sep", "nirioiosauto_08Sep_ios_CT_adjust.json"), encoding="utf-8"))
CAP = next(r for r in RECS if r["sid"] == "39")
Q = CAP["url"].split("?", 1)[1]
FIELDS = dict(urllib.parse.parse_qsl(Q, keep_blank_values=True))
CLIENT_SDK = next(v for k, v in CAP["request_headers"] if k.lower() == "client-sdk")
UA = next(v for k, v in CAP["request_headers"] if k.lower() == "user-agent")
gj = json.loads(CAP["response"])
g_attr = gj["attribution"]
print("capture consent-host verdict: %s / %s / %s"
      % (g_attr.get("network"), g_attr.get("tracker_token"),
         g_attr.get("campaign")))
print("capture device: idfa=%s idfv=%s dedupe=%s"
      % (FIELDS.get("idfa"), FIELDS.get("idfv"),
         FIELDS.get("primary_dedupe_token")))

# analytics host path: att_status=3 -> 0, host consent -> analytics
A = dict(FIELDS)
A["att_status"] = "0"
HOST = "https://analytics.adjust.com"
SEC = int(time.time()) - 2
A["created_at"] = __import__("datetime").datetime.fromtimestamp(
    SEC + 5*3600 + 30*60).__format__("%Y-%m-%dT%H:%M:%S.")+"000Z+0530"
A["sent_at"] = __import__("datetime").datetime.fromtimestamp(
    SEC + 1 + 5*3600 + 30*60).__format__("%Y-%m-%dT%H:%M:%S.")+"000Z+0530"

auth, blob = sg.sign_request(A, "attribution", second=SEC, client_sdk=CLIENT_SDK)
url = HOST + "/attribution?" + urllib.parse.urlencode(A)
r = _rq.get(url, headers={"User-Agent": UA, "Client-Sdk": CLIENT_SDK,
                          "Authorization": auth, "Accept-Encoding": "gzip"},
            timeout=30)
body = r.text
if r.headers.get("content-encoding") == "gzip":
    try: body = __import__("gzip").decompress(r.content).decode("utf-8","replace")
    except Exception: pass
print("\n[analytics-host replay] HTTP %d  (sig %s..)\n   %s"
      % (r.status_code, blob.hex().upper()[:16], body[:300]))
try:
    a = r.json().get("attribution", {})
    print("\nanalytics-host verdict: %s / %s" % (a.get("network"), a.get("tracker_token")))
    same = (a.get("network") == g_attr.get("network")
            and a.get("tracker_token") == g_attr.get("tracker_token"))
    if same:
        print("=> SAME as logs (analytics host honors the stale booking)")
    elif a.get("network") != "Organic":
        print("=> NON-ORGANIC but drifted from capture (host accepts nirio sig)")
    else:
        print("=> Organic on analytics host too (nirio analytics-host behavior)")
except ValueError:
    print("non-JSON body")
json.dump({"host": "analytics.adjust.com", "att_status": "0",
           "verdict": (r.status_code, body[:300])},
          open("analytics_host_replay_result.json", "w"), indent=1)
