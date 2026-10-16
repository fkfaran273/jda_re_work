# -*- coding: utf-8 -*-
import uuid
from curl_cffi import requests as cr

IDFA = str(uuid.uuid4()).upper()
GAID = str(uuid.uuid4())
URL = ("https://adjar.trckswrm.com/click?offer_id=5395&pub_id=52"
       "&pub_sub_id=1298014792&pub_click_id=z" + uuid.uuid4().hex[:12] +
       "&idfa=" + IDFA + "&gaid=" + GAID + "&app=com.unknown&creative=cr_1")
s = cr.Session(impersonate="chrome131_android")
r = s.get(URL, timeout=30, allow_redirects=False, verify=False,
          headers={"User-Agent": "Mozilla/5.0 (Linux; Android 12; moto g42) "
                                 "AppleWebKit/537.36 (KHTML, like Gecko) "
                                 "Chrome/131.0.0.0 Mobile Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,"
                             "application/xml;q=0.9,*/*;q=0.8"})
print("status", r.status_code)
print("headers:")
for k, v in r.headers.items():
    print("   %s: %s" % (k, str(v)[:200]))
print("body len", len(r.content))
print("body:", repr(r.text[:1500]))
