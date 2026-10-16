# -*- coding: utf-8 -*-
"""discover_offer.py -- try to identify the app behind trckswrm offer 5395."""
import uuid
from curl_cffi import requests as cr

UA = {"User-Agent": "Mozilla/5.0 (Linux; Android 12; moto g42) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Mobile Safari/537.36"}
s = cr.Session(impersonate="chrome131_android")
IDFA = str(uuid.uuid4()).upper()
GAID = str(uuid.uuid4())

tries = [
    ("base", "https://adjar.trckswrm.com/"),
    ("click no offer", "https://adjar.trckswrm.com/click?pub_id=52"),
    ("offer path", "https://adjar.trckswrm.com/offer/5395"),
    ("offers", "https://adjar.trckswrm.com/offers"),
    ("api offer", "https://adjar.trckswrm.com/api/offer/5395"),
    ("click with app", "https://adjar.trckswrm.com/click?offer_id=5395&pub_id=52"
                       "&pub_sub_id=1298014792&pub_click_id=z"
                       + uuid.uuid4().hex[:12] + "&idfa=" + IDFA
                       + "&gaid=" + GAID + "&app=in.hanafintech"
                       "&creative=cr_1"),
    ("click redirect param", "https://adjar.trckswrm.com/click?offer_id=5395"
                             "&pub_id=52&pub_sub_id=1298014792"
                             "&pub_click_id=z" + uuid.uuid4().hex[:12]
                             + "&idfa=" + IDFA + "&gaid=" + GAID
                             + "&redirect=https://example.com/x"),
]
for name, url in tries:
    try:
        r = s.get(url, timeout=20, allow_redirects=False, verify=False,
                  headers=UA)
        print("%-20s %s len=%s loc=%s" % (name, r.status_code, len(r.content),
                                          r.headers.get("Location", "")[:90]))
        if r.content and len(r.content) < 400:
            print("      body:", repr(r.text[:300]))
    except Exception as e:
        print("%-20s ERR %r" % (name, e))
