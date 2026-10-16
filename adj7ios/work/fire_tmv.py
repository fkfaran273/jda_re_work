# -*- coding: utf-8 -*-
"""fire_tmv.py -- the trckswrm click -> adjust 20yvzdd5 chain, then a fresh
adj7-iOS install behind the SAME click (S2S-style tracker: the click is a
logging call; the join is device-id based).

Click chain (as the browser made it):
  1. GET adjar.trckswrm.com/click?offer_id=5395&pub_id=52&pub_sub_id=<id>
     &pub_click_id=<id>&idfa=<idfa>&gaid=<gaid>&app=<app>&creative=<cr>
     -> 302 https://app.adjust.com/20yvzdd5?campaign=TMV+May_Derby
        &adgroup=NP_SH_Q&install_callback=...&event_callback_...
  2. GET the adjust link (registers the click)
     -> 302 https://apps.apple.com/app/id1298014792?mt=8

Install: our adj7-iOS funnel behind the SAME idfa, with the campaign wired
for tracker 20yvzdd5 (native_version/headers_id/cert TBD by probe).
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import uuid

from curl_cffi import requests as cr

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) "
      "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 "
      "Mobile/15E148 Safari/604.1")

PUB_SUB = os.environ.get("TMV_PUB_SUB", "1298014792")
PUB_CLICK = "z" + uuid.uuid4().hex[:12]
IDFA = (os.environ.get("TMV_IDFA") or str(uuid.uuid4())).upper()
GAID = os.environ.get("TMV_GAID") or str(uuid.uuid4())
APP = os.environ.get("TMV_APP", "com.unknown")
CREATIVE = os.environ.get("TMV_CREATIVE", "cr_1")

CLICK = ("https://adjar.trckswrm.com/click?offer_id=5395&pub_id=52"
         "&pub_sub_id=" + PUB_SUB + "&pub_click_id=" + PUB_CLICK +
         "&idfa=" + IDFA + "&gaid=" + GAID + "&app=" + APP +
         "&creative=" + CREATIVE)

print("IDFA      :", IDFA)
print("pub_sub   :", PUB_SUB, "| pub_click:", PUB_CLICK)
print("click URL :", CLICK, flush=True)

s = cr.Session(impersonate="safari17_0")
u = CLICK
adjust_url = None
for hop in range(10):
    r = s.get(u, timeout=30, allow_redirects=False, verify=False,
              headers={"User-Agent": UA, "Accept": "text/html,application/"
                       "xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
    loc = r.headers.get("Location", "")
    print("hop %d -> %s %s" % (hop, r.status_code, u[:150]), flush=True)
    if loc:
        print("      loc=%s" % loc[:200], flush=True)
    if not loc:
        break
    if "app.adjust.com" in loc:
        adjust_url = loc
    if loc.startswith("http"):
        u = loc
        continue
    print("      terminal:", loc[:200], flush=True)
    break

print()
print("ADJUST URL:", (adjust_url or "")[:300])
print("TRACKER   :", urllib.parse.urlsplit(
    adjust_url or "").path.strip("/"))
qs = dict(urllib.parse.parse_qsl(
    urllib.parse.urlsplit(adjust_url or "").query))
print("QS keys   :", sorted(qs.keys()))
print("campaign  :", qs.get("campaign"), "| adgroup:", qs.get("adgroup"))

out = {"idfa": IDFA, "gaid": GAID, "pub_sub": PUB_SUB,
       "pub_click": PUB_CLICK, "click": CLICK,
       "adjust_url": adjust_url, "qs": qs}
with open(os.path.join(HERE, "tmv_click.json"), "w") as f:
    json.dump(out, f, indent=1)
print("wrote tmv_click.json")
