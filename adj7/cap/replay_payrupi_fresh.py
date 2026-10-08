"""replay_payrupi_fresh.py — THE MAJOR RULE, properly: replay the genuine
payrupi attribution with FRESH times (created_at/sent_at = now, +0530 like
the capture) and our fresh adj7_pure signature.  The device identity
(gps_adid/android_uuid/push_token) stays the genuine Pixel's.  The genuine
state = NON-ORGANIC (tracker 248wk8ym, VL-Alliance::HM2) — the replay must
return it.

    python replay_payrupi_fresh.py
"""
import json
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "..")
sys.path.insert(0, "work")
import adj7_pure as sg
from curl_cffi import requests as cr

D = json.load(open("payrupi_extract.json"))
QUERY = D["queries"][0].split("?", 1)[1]
FIELDS = dict(urllib.parse.parse_qsl(QUERY, keep_blank_values=True))
CERT = "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"   # in.hanafintech (== record "c")
CS = "android5.6.0"
sg.CERT_SHA1 = CERT

URL = "https://app.adjust.com/attribution?" + QUERY

for block2 in (False, True):
    # fresh times, the capture's local-offset shape (+0530)
    now = datetime.now(timezone(timedelta(hours=5, minutes=30)))
    stamp = now.strftime("%Y-%m-%dT%H:%M:%S.") + "%03d" % (now.microsecond // 1000) + "Z+0530"
    FIELDS["created_at"] = stamp
    FIELDS["sent_at"] = stamp

    blob, auth = sg.mint_adj7("attribution", FIELDS, unix_sec=int(time.time()),
                              client_sdk=CS, include_block2=block2)
    S = cr.Session(impersonate="chrome131_android")
    r = S.get(URL, headers={
        "Client-SDK": CS,
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 17; Pixel 6a Build/CP2A.260705.006)",
        "Authorization": auth, "Accept-Encoding": "gzip"}, timeout=30)
    nonorg = "248wk8ym" in r.text
    print("block2=%-5s -> HTTP %d  %s" % (block2, r.status_code,
                                          "NON-ORGANIC ***" if nonorg else "Organic"))
    print("   ", r.text[:200])
