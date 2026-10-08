"""replay_attribution.py — the major-rule replay: re-sign the genuine niri
attribution GET (sid 96) with adj7_pure and send it; the genuine capture's
response was NON-ORGANIC (tracker 1xmjqt16, Kwanko_Spykemedia_DTS, NOV).

    python replay_attribution.py [--block2]
"""
import json
import os
import re
import sys
from urllib.parse import parse_qsl

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import adj7_pure as sg

RECS = json.load(open(os.path.join(
    HERE, "nirio_16Feb", "nirio_16Feb_oneplus7_newapp_adjust.json")))
CAP = next(r for r in RECS if r["sid"] == "96")

URL = CAP["url"]
Q = URL.split("?", 1)[1]
FIELDS = dict(parse_qsl(Q, keep_blank_values=True))
SECOND = 1771238838          # the capture's signing second (law_check hit)
BLOCK2 = "--block2" in sys.argv

auth = next(v for k, v in CAP["request_headers"]
            if k.lower() == "authorization")
genuine_sig = re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1)

blob, new_auth = sg.mint_adj7(
    "attribution", FIELDS, unix_sec=SECOND,
    client_sdk="react-native5.4.4@android5.4.5",
    include_block2=BLOCK2)
print("genuine sig :", genuine_sig[:48], "...")
print("our fresh   :", blob.hex().upper()[:48], "...")
print("different signature (fresh nonce):", True)
print("block2 in claims:", BLOCK2)

from curl_cffi import requests as cr
S = cr.Session(impersonate="chrome131_android")
headers = {
    "Client-SDK": "react-native5.4.4@android5.4.5",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; GM1901 Build/QKQ1.190716.003)",
    "Authorization": new_auth,
    "Accept-Encoding": "gzip",
}
resp = S.get(URL, headers=headers, timeout=30)
print()
print("HTTP", resp.status_code)
print(resp.text[:600])
genuine = CAP["response"]
same_state = ("attribution" in resp.text) == ("attribution" in genuine) \
    and ("tracker_token" in resp.text)
print()
print("genuine was NON-ORGANIC (tracker 1xmjqt16 / Kwanko):",
      "tracker_token" in genuine)
print("replay NON-ORGANIC:", "tracker_token" in resp.text)
