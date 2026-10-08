"""Full replay of the niceone 8-Oct capture: signed /session -> signed /attribution,
expecting the logged 'No User Consent' attribution object.
"""
import json, sys, os, time
from datetime import datetime
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
sess_rec = [r for r in recs if r["params"].get("session_count") == "1"][0]
attr_rec = [r for r in recs if r["params"].get("initiated_by") == "sdk"][-1]

def clean(p):
    q = dict(p)
    for k in list(q):
        if len(q[k]) > 2 and not q[k][:-1].isprintable():
            q[k] = q[k][0]          # carve bleed: att_status='0q' -> '0'
        elif k == "att_status":
            q[k] = "0"
    return q

def fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0300" % (dt.microsecond // 1000)

S = cr.Session(impersonate="safari17_0")
HOST = "https://analytics.adjust.com"

def signed(method, path, params, kind):
    t = int(time.time()) + 1
    while time.time() < t:
        time.sleep(0.02)
    p = dict(params)
    now = fmt(datetime.utcnow())
    p["created_at"] = now
    p["sent_at"] = now
    auth = sg.sign_request(p, kind, c=CAMPAIGN, second=t)
    h = {"User-Agent": UA, "Client-Sdk": CAMPAIGN["adjust"]["sdk"], "Authorization": auth}
    if method == "POST":
        h["Content-Type"] = "application/x-www-form-urlencoded"
        return S.post(HOST + path, data=p, headers=h, timeout=30)
    return S.get(HOST + path + "?" + urlencode(p), headers=h, timeout=30)

sp = clean(sess_rec["params"])
print("[1] POST /session ...", flush=True)
r = signed("POST", "/session", sp, "session")
print("    status", r.status_code, "|", r.text[:300], flush=True)
time.sleep(8)

ap = clean(attr_rec["params"])
print("[2] GET /attribution ...", flush=True)
r2 = signed("GET", "/attribution", ap, "attribution")
print("    status", r2.status_code, flush=True)
print("    body:", r2.text[:700], flush=True)
try:
    a = r2.json().get("attribution", {})
    print("\n  tracker_token:", a.get("tracker_token"))
    print("  tracker_name :", a.get("tracker_name"))
    print("  network      :", a.get("network"))
    print("  engagement   :", a.get("engagement_time"))
    print("  reattributed :", a.get("is_reattributed"))
    if a.get("tracker_name") == "No User Consent":
        print("\n  MATCH: replay reproduces the captured 'No User Consent' state")
except Exception as e:
    print("    json err", e)
