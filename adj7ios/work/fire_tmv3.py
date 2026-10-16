# -*- coding: utf-8 -*-
"""fire_tmv3.py -- iOS mobile Safari navigation fingerprint (the offer is an
iOS app; the tracker may only redirect mobile-iOS browsers)."""
import json
import os
import uuid

from curl_cffi import requests as cr

HERE = os.path.dirname(os.path.abspath(__file__))
IDFA = (os.environ.get("TMV_IDFA") or str(uuid.uuid4())).upper()
GAID = os.environ.get("TMV_GAID") or str(uuid.uuid4())
PUB_CLICK = "z" + uuid.uuid4().hex[:12]
APPS = ["com.berain.berain", "1298014792", "berain", "com.berain.berain"]

CLICK = ("https://adjar.trckswrm.com/click?offer_id=5395&pub_id=52"
         "&pub_sub_id=1298014792&pub_click_id=" + PUB_CLICK +
         "&idfa=" + IDFA + "&gaid=" + GAID + "&app=%s"
         "&creative=NP_SH_Q")

IOS_HDRS = {
    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) "
                  "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                  "Version/16.6 Mobile/15E148 Safari/604.1",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
}

for app in APPS:
    url = CLICK % app
    for imp in ("safari17_0", "safari16_0", "chrome131"):
        try:
            s = cr.Session(impersonate=imp)
            r = s.get(url, timeout=25, allow_redirects=False, verify=False,
                      headers=IOS_HDRS)
            loc = r.headers.get("Location", "")
            print("app=%-20s imp=%-11s -> %s loc=%s"
                  % (app, imp, r.status_code, loc[:120]), flush=True)
            if r.status_code in (301, 302, 303, 307, 308) and loc:
                print("  302 FOUND ->", loc[:300])
                json.dump({"idfa": IDFA, "gaid": GAID, "click": url,
                           "adjust_url": loc, "app_param": app,
                           "impersonate": imp},
                          open(os.path.join(HERE, "tmv_click.json"), "w"),
                          indent=1)
                raise SystemExit(0)
        except SystemExit:
            raise
        except Exception as e:
            print("app=%-20s imp=%-11s ERR %r" % (app, imp, e))
print("no 302 from any combination")
