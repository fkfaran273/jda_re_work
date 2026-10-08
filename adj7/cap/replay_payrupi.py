"""replay_payrupi.py — THE MAJOR RULE: re-sign the genuine payrupi
attribution GET (fresh, today, non-organic VL-Alliance) with adj7_pure
and send it.  The genuine response was tracker 248wk8ym /
VL-Alliance::HM2::HM2_1722_ — our replay must reproduce it.

    python replay_payrupi.py
"""
import json
import sys
import urllib.parse
from datetime import datetime, timezone, timedelta

sys.path.insert(0, "..")
import adj7_pure as sg
from curl_cffi import requests as cr

D = json.load(open("payrupi_extract.json"))
URL = "https://app.adjust.com" + D["queries"][0]
FIELDS = dict(urllib.parse.parse_qsl(D["queries"][0].split("?", 1)[1],
                                     keep_blank_values=True))
CERT = "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"
CS = "android5.6.0"

# signing second: brute ±6 s around created_at (11:55:45 +0530)
ca = datetime.strptime("2026-10-06T11:55:45", "%Y-%m-%dT%H:%M:%S")
ca = ca.replace(tzinfo=timezone(timedelta(hours=5, minutes=30)))
base = int(ca.timestamp())
seed = None
for off in range(-6, 7):
    sec = base + off
    if sg.make_header(sec) == blob_head_check if False else False:
        pass
# simpler: find the seed from the genuine signature's header
sig0 = D["sigs"][0]["sig"]
head = bytes.fromhex(sig0)[:16]
for off in range(-30, 31):
    if sg.make_header(base + off) == head:
        seed = base + off
        break
print("genuine signing second:", seed, "(created", base, ")")

genuine_resp = [r for r in D["responses"] if "248wk8ym" in r][0]
print("genuine response:", genuine_resp[:200])

sg.CERT_SHA1 = CERT

for block2 in (True, False):
    blob, auth = sg.mint_adj7(
        "attribution", FIELDS, unix_sec=seed or base,
        client_sdk=CS, include_block2=block2)
    S = cr.Session(impersonate="chrome131_android")
    r = S.get(URL, headers={
        "Client-SDK": CS,
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 17; Pixel 6a Build/CP2A.260705.006)",
        "Authorization": auth,
        "Accept-Encoding": "gzip"}, timeout=30)
    print()
    print("block2=%s -> HTTP %s" % (block2, r.status_code))
    print(r.text[:300])
    print("NON-ORGANIC MATCH:", "248wk8ym" in r.text)
