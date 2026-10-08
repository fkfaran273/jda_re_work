"""replay_payrupik_new.py -- THE MAJOR RULE on the FRESH payrupik capture
(cap/payrupik_new, moto g42, Android 12, 2026-10-06 15:47 +0530).

Replay the genuine attribution GET (sid 44) with FRESH created_at/sent_at
and OUR adj7_pure signature (headers_id 8, native 3.62.0, the moto g42
identity, CERT = the app's Play cert SHA-1).  The genuine state is
NON-ORGANIC (tracker 248wk8ym / VL-Alliance::HM2::HM2_1722_) -- the replay
must return the SAME non-organic response, or the signature rule is wrong.

    python replay_payrupik_new.py
"""
import json
import re
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7")
import adj7_pure as sg
from curl_cffi import requests as cr

D = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json"))
CAP = next(e for e in D if str(e["sid"]) == "44")
Q = CAP["url"].split("?", 1)[1]
FIELDS = dict(urllib.parse.parse_qsl(Q, keep_blank_values=True))

CERT = "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"   # in.hanafintech
CS = "android5.6.0"
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
sg.CERT_SHA1 = CERT
sg.CLIENT_SDK = CS

genuine = CAP["response"]
print("genuine :", genuine[:220])
print()

for block2 in (False, True):
    now = datetime.now(timezone(timedelta(hours=5, minutes=30)))
    stamp = (now.strftime("%Y-%m-%dT%H:%M:%S.")
             + "%03d" % (now.microsecond // 1000) + "Z+0530")
    FIELDS["created_at"] = stamp
    FIELDS["sent_at"] = stamp
    sec = int(time.time())

    blob, auth = sg.sign_request(
        FIELDS, "attribution", second=sec, cert_sha1=CERT,
        client_sdk=CS, include_block2=block2,
        headers_id="8", native_version="3.62.0")

    url = "https://app.adjust.com/attribution?" + urllib.parse.urlencode(FIELDS)
    S = cr.Session(impersonate="chrome131_android")
    r = S.get(url, headers={
        "Client-SDK": CS, "User-Agent": UA,
        "Authorization": auth, "Accept-Encoding": "gzip"}, timeout=30)
    nonorg = "248wk8ym" in r.text
    print("block2=%-5s -> HTTP %d  %s" % (block2, r.status_code,
                                         "NON-ORGANIC MATCH ***" if nonorg else "Organic/other"))
    print("   ", r.text[:220])
    print()
