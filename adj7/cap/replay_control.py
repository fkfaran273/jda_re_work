"""replay_control.py -- control: send the GENUINE attribution request
byte-identical (same URL incl. original created_at/sent_at, same original
Authorization header).  If this no longer returns the genuine non-organic
state, the gap is server-side state, not our signature.
"""
import json
import sys

import requests
D = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json"))
CAP = next(e for e in D if str(e["sid"]) == "44")
auth = None
ua = None
for k, v in CAP["request_headers"]:
    if k.lower() == "authorization":
        auth = v
    if k.lower() == "user-agent":
        ua = v
r = requests.get(CAP["url"], headers={
    "Client-SDK": "android5.6.0", "User-Agent": ua,
    "Authorization": auth, "Accept-Encoding": "gzip"}, timeout=30)
print("HTTP", r.status_code)
print(r.text[:400])
print("genuine non-organic:", "248wk8ym" in CAP["response"])
print("replay non-organic:", "248wk8ym" in r.text)
