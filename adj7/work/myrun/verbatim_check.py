"""verbatim_check.py -- proof that the attribution REPLAY (byte-identical
URL + original Authorization blob) still returns the captured NON-ORGANIC
verdict, the same way PROBE VERBATIM / PROBE G did."""
import json
import os

from curl_cffi import requests as cr

D = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json"))
CAP = next(e for e in D if str(e["sid"]) == "44")
for k, v in CAP["request_headers"]:
    pass
auth = None
ua = None
for k, v in CAP["request_headers"]:
    if k.lower() == "authorization":
        auth = v
    if k.lower() == "user-agent":
        ua = v

S = cr.Session(impersonate="chrome131_android")
r = S.get(CAP["url"], headers={
    "Client-SDK": "android5.6.0",
    "User-Agent": ua,
    "Authorization": auth,
    "Accept-Encoding": "gzip",
}, timeout=30)
print("HTTP", r.status_code)
print(r.text[:500])
print()
print("VERDICTL:", "NON-ORGANIC (248wk8ym / VL-Alliance)"
      if "248wk8ym" in r.text else "Organic")
