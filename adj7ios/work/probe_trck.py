# -*- coding: utf-8 -*-
"""probe_trck.py -- fire the trckswrm click link with fresh ids and follow
the redirect chain to identify the Adjust app/tracker."""
import re
import sys
import time
import urllib.parse
import uuid

from curl_cffi import requests as cr

IDFA = str(uuid.uuid4()).upper()
GAID = str(uuid.uuid4())
PUB_SUB = "1298014792"
PUB_CLICK = "z" + uuid.uuid4().hex[:12]

URL = ("https://adjar.trckswrm.com/click?offer_id=5395&pub_id=52"
       "&pub_sub_id=" + PUB_SUB +
       "&pub_click_id=" + PUB_CLICK +
       "&idfa=" + IDFA +
       "&gaid=" + GAID +
       "&app=com.unknown"          # placeholder, refined after the first hop
       "&creative=cr_1")

print("IDFA:", IDFA)
print("GAID:", GAID)
print("click:", URL, flush=True)

s = cr.Session(impersonate="chrome131_android")
u = URL
for hop in range(12):
    r = s.get(u, timeout=30, allow_redirects=False, verify=False,
              headers={"User-Agent":
                       "Mozilla/5.0 (Linux; Android 12; moto g42) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/131.0.0.0 Mobile Safari/537.36",
                       "Accept": "text/html,application/xhtml+xml,"
                                 "application/xml;q=0.9,*/*;q=0.8"})
    loc = r.headers.get("Location", "")
    print("hop %d -> %s  %s" % (hop, r.status_code, u[:170]), flush=True)
    if loc:
        print("        loc=%s" % loc[:250], flush=True)
    ck = r.headers.get("Set-Cookie", "")
    if ck:
        print("        cookie=%s" % ck[:150], flush=True)
    if not loc:
        print("        body head:", r.text[:180].replace("\n", " "),
              flush=True)
        break
    if not loc.startswith("http"):
        print("        non-http terminal:", loc[:200], flush=True)
        break
    u = loc
