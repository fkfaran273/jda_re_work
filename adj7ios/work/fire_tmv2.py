# -*- coding: utf-8 -*-
"""fire_tmv2.py -- the trckswrm click with a full browser navigation
fingerprint (the tracker 200s a bare client but 302s a real browser)."""
import json
import os
import sys
import urllib.parse
import uuid

from curl_cffi import requests as cr

HERE = os.path.dirname(os.path.abspath(__file__))
IDFA = (os.environ.get("TMV_IDFA") or str(uuid.uuid4())).upper()
GAID = os.environ.get("TMV_GAID") or str(uuid.uuid4())
PUB_SUB = os.environ.get("TMV_PUB_SUB", "1298014792")
PUB_CLICK = "z" + uuid.uuid4().hex[:12]
APP = "com.berain.berain"

CLICK = ("https://adjar.trckswrm.com/click?offer_id=5395&pub_id=52"
         "&pub_sub_id=" + PUB_SUB + "&pub_click_id=" + PUB_CLICK +
         "&idfa=" + IDFA + "&gaid=" + GAID + "&app=" + APP +
         "&creative=NP_SH_Q")

HDRS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8,"
              "application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", '
                 '"Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
}

print("IDFA:", IDFA, "| app:", APP)
print("click:", CLICK, flush=True)

for imp in ("chrome124", "safari17_0", "chrome131"):
    try:
        s = cr.Session(impersonate=imp)
        r = s.get(CLICK, timeout=30, allow_redirects=False, verify=False,
                  headers=HDRS)
        loc = r.headers.get("Location", "")
        print("impersonate=%-12s -> %s loc=%s"
              % (imp, r.status_code, loc[:150]), flush=True)
        if loc and r.status_code in (301, 302, 303, 307, 308):
            print("GOT THE 302 with", imp, flush=True)
            print("  location:", loc[:400])
            json.dump({"idfa": IDFA, "gaid": GAID, "pub_sub": PUB_SUB,
                       "pub_click": PUB_CLICK, "click": CLICK,
                       "adjust_url": loc,
                       "impersonate": imp},
                      open(os.path.join(HERE, "tmv_click.json"), "w"),
                      indent=1)
            break
    except Exception as e:
        print("impersonate=%-12s ERR %r" % (imp, e))
