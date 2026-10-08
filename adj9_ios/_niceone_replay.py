"""Replay the niceone 8-Oct capture's /attribution request, signed with our adj9 signer."""
import json, sys, os, time
from datetime import datetime, timedelta
from urllib.parse import urlencode
from curl_cffi import requests as cr

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9ios_pure as sg

CAMPAIGN = {
    "app_name": "niceoneautoios",
    "device_name": "iPhone12,1",
    "os_name": "ios",
    "os_version": "26.5",
    "head_phase": [0x09],
    "adjust": {
        "app_token": "1ri26ekrhwtc",
        "sdk": "ios5.8.0",
        "adj_signing_id": "1500000",
        "headers_id": "10",
        "algorithm": "adj9",
        "native_version": "5.0.0",
        "adj_verification": "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb",
    },
}
UA = "NiceOneAuto/5.8.7 CFNetwork/3860.600.12 Darwin/25.5.0"

recs = json.load(open(os.path.join(HERE, "_niceone_reqs.json")))
attrs = [r for r in recs if "/attribution" in open(os.devnull, 'r').read()] if False else None
# pick the record whose query has initiated_by=sdk and no event_token (the GET /attribution)
cand = [r for r in recs if r["params"].get("initiated_by") == "sdk"
        and "event_token" not in r["params"]
        and "session_count" not in r["params"]]
print("candidate attribution records:", [r["i"] for r in cand])
r = cand[-1]
p = dict(r["params"])
p["att_status"] = p.get("att_status", "0")[0]  # strip carve bleed ('0q'->'0')
now = datetime.utcnow()
def fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0300" % (dt.microsecond // 1000)
p["created_at"] = p["sent_at"] = fmt(now)
p["initiated_by"] = p.get("initiated_by", "sdk")

HOST = "https://consent.adjust.com" if p["att_status"] == "3" else "https://analytics.adjust.com"
S = cr.Session(impersonate="safari17_0")
t = int(time.time()) + 1
while time.time() < t:
    time.sleep(0.02)
auth = sg.sign_request(p, "attribution", c=CAMPAIGN, second=t)
h = {"User-Agent": UA, "Client-Sdk": CAMPAIGN["adjust"]["sdk"], "Authorization": auth}
url = HOST + "/attribution?" + urlencode(p)
print("GET", url[:120], "...")
resp = S.get(url, headers=h, timeout=30)
print("status:", resp.status_code)
print(resp.text[:800])
try:
    a = resp.json().get("attribution", {})
    print("\ntracker:", a.get("tracker_token"), "|", a.get("tracker_name"),
          "| engagement:", a.get("engagement_time"))
except Exception as e:
    print("json err", e)
