# -*- coding: utf-8 -*-
"""Cross-signing test (analytics host): use the CAPTURE device identity
(idfa/idfv/dedupe/app_token from sid-39) but the ADJ9-iOS auth HEADER SHAPE
(1500000/adj9/10/5.0.0 + adj_verification) on analytics.adjust.com.
Question: does nirio adj7 analytics host WANT adj9-style params (i.e. our
"signature maker" for nirio analytics is genuinely incomplete), or does it
return Organic for nirio regardless of auth shape (app behavior)?

If adj9-shape flips to non-organic -> our nirio analytics "signature maker"
is incomplete (needs adj9-style header on analytics host).
If still Organic -> analytics-host non-organic is app-specific (penti yes,
nirio no); our nirio adj7 analytics sig is accepted-but-Organic.
"""
import json, os, sys, time, urllib.parse, base64
from datetime import datetime, timezone
import requests as _rq
import adj7_ios_pure as sg

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

RECS = json.load(open(os.path.join("nirio_08Sep",
    "nirioiosauto_08Sep_ios_CT_adjust.json"), encoding="utf-8"))
CAP = next(r for r in RECS if r["sid"] == "39")
Q = CAP["url"].split("?", 1)[1]
FIELDS = dict(urllib.parse.parse_qsl(Q, keep_blank_values=True))
CLIENT_SDK = next(v for k, v in CAP["request_headers"] if k.lower() == "client-sdk")
UA = next(v for k, v in CAP["request_headers"] if k.lower() == "user-agent")
g_attr = json.loads(CAP["response"]).get("attribution", {})

# analytics host shape for the MAP (att_status 3->0 stays; that's the device)
A = dict(FIELDS)
A["att_status"] = "0"
HOST = "https://analytics.adjust.com"
SEC = int(time.time()) - 2
Z = "+0530"
CAT = datetime.fromtimestamp(SEC + 5*3600 + 30*60, timezone.utc).strftime(
    "%Y-%m-%dT%H:%M:%S.") + "000Z" + Z
SAT = datetime.fromtimestamp(SEC + 1 + 5*3600 + 30*60, timezone.utc).strftime(
    "%Y-%m-%dT%H:%M:%S.") + "000Z" + Z
A["created_at"] = CAT
A["sent_at"] = SAT

# sign with OUR nirio adj7 maker (control) AND build an ADJ9-shape header
# manually over the same blob (so the only diff is the header fields).
auth7, blob = sg.sign_request(A, "attribution", second=SEC, client_sdk=CLIENT_SDK)
ADJ_V = "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"
auth9 = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
         'headers_id="10",native_version="5.0.0",adj_verification="%s"'
         % (blob.hex().upper(), ADJ_V))

def get(auth):
    url = HOST + "/attribution?" + urllib.parse.urlencode(A)
    r = _rq.get(url, headers={"User-Agent": UA, "Client-Sdk": CLIENT_SDK,
                              "Authorization": auth, "Accept-Encoding": "gzip"},
                timeout=30)
    b = r.text
    if r.headers.get("content-encoding") == "gzip":
        try: b = __import__("gzip").decompress(r.content).decode("utf-8","replace")
        except Exception: pass
    try: a = r.json().get("attribution", {})
    except ValueError: a = {}
    return r.status_code, a, b[:200]

print("capture consent verdict: %s / %s / %s"
      % (g_attr.get("network"), g_attr.get("tracker_token"), g_attr.get("campaign")))
print("device: idfa=%s idfv=%s dedupe=%s app_token=%s"
      % (A.get("idfa"), A.get("idfv"), A.get("primary_dedupe_token"),
         A.get("app_token")))

# control: our nirio adj7 header (expected Organic again)
st7, a7, b7 = get(auth7)
print("\n[nirio adj7 auth, analytics host] HTTP %d  %s"
      % (st7, (a7.get("network"), a7.get("tracker_token"))))
print("   body:", b7)

# test: adj9-shape header, SAME blob, SAME map, SAME device, analytics host
st9, a9, b9 = get(auth9)
print("\n[adj9-shape auth, analytics host] HTTP %d  %s"
      % (st9, (a9.get("network"), a9.get("tracker_token"))))
print("   body:", b9)

print("\n=================== READOUT ====================")
if st9 != 200:
    print("adj9-shape REJECTED by analytics host -> our nirio adj7 analytics sig")
    print("  is incomplete (host wants adj9-style header on analytics).")
elif a9.get("network") != "Organic":
    print("adj9-shape returned NON-ORGANIC (network=%s tk=%s) for NIRIO device"
          % (a9.get("network"), a9.get("tracker_token")))
    print("  -> analytics host DOES want adj9-style header; our nirio adj7 maker")
    print("     is incomplete for analytics host (missing adj_verification / adj9)")
elif a7.get("network") != "Organic":
    print("control (nirio adj7) was NON-ORGANIC too -> host honors stale booking")
    print("  on analytics for nirio (contradicts earlier Organic).")
else:
    print("adj9-shape ALSO Organic (same adid %s) -> analytics host returns "
          "Organic for nirio device regardless of auth shape."
          % a9.get("adid"))
    print("  => analytics-host non-organic is app-specific (penti vs nirio); our")
    print("     nirio adj7 analytics sig is ACCEPTED but gets Organic.")

json.dump({
    "host": "analytics.adjust.com", "att_status": "0",
    "nirio_adj7": {"status": st7, "network": a7.get("network"),
                   "tracker_token": a7.get("tracker_token"),
                   "body": b7},
    "adj9_shape": {"status": st9, "network": a9.get("network"),
                   "tracker_token": a9.get("tracker_token"),
                   "body": b9},
}, open("adj9shape_analytics_result.json", "w"), indent=1)
