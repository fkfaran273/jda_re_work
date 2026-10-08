"""deferred_reask.py — wait out the attribution ask_in window, then re-ask
the moto's fresh install attribution with OUR pure signature (the major
rule) and write the verdict.

    python deferred_reask.py
"""
import json
import sys
import time
import urllib.parse
from datetime import datetime

sys.path.insert(0, "..")
sys.path.insert(0, "work")
import adj7_pure as sg
from curl_cffi import requests as cr

calls = json.load(open("fresh_install_maps.json"))
attr = next(c for c in calls if c["n"] == 3)
GAID = attr["arg1"]["gps_adid"]
CERT = "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"
sg.CERT_SHA1 = CERT
sg.CLIENT_SDK = "android5.6.0"

FIELDS = dict(attr["arg1"])
for k in ("adj_signing_id", "algorithm", "headers_id", "native_version",
          "endpoint"):
    FIELDS.pop(k, None)
# fresh times on every ask (the device re-asks with fresh stamps too)
def fresh_fields():
    f = dict(FIELDS)
    now = time.time()
    stamp = (datetime.utcfromtimestamp(now + 19800)
             .strftime("%Y-%m-%dT%H:%M:%S.") + "%03d" % (int(now * 1000) % 1000)
             + "Z+0530")
    f["created_at"] = stamp
    f["sent_at"] = stamp
    return f

def ask():
    f = fresh_fields()
    auth = sg.mint_adj7("attribution", f, unix_sec=int(time.time()),
                        client_sdk="android5.6.0", include_block2=True)
    r = cr.get("https://app.adjust.com/attribution?" + urllib.parse.urlencode(f),
               headers={"Client-SDK": "android5.6.0",
                        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; "
                                      "moto g42 Build/S2SE32.28-28-4)",
                        "Authorization": auth,
                        "Accept-Encoding": "gzip"}, timeout=30)
    return r.status_code, r.text

# wait out the ask_in window (~6335 s from the 400 at ~15:25 -> ends ~17:11)
ask_in_s = 6335
wait = max(0, ask_in_s - (time.time() - ASK_ANCHOR)) if False else ask_in_s
print("[%s] waiting %d s for the ask_in window..." % (
    datetime.now().strftime("%H:%M:%S"), ask_in_s), flush=True)
time.sleep(ask_in_s)

for attempt in (1, 2, 3):
    code, body = ask()
    verdict = "PENDING/400" if code == 400 else (
        "NON-ORGANIC" if '"network":"Organic"' not in body else "Organic")
    print("[%s] re-ask #%d -> HTTP %d  %s" % (
        datetime.now().strftime("%H:%M:%S"), attempt, code, verdict), flush=True)
    print("   ", body[:250], flush=True)
    if code == 200:
        with open("deferred_verdict.json", "w") as f:
            json.dump({"http": code, "verdict": verdict, "body": body}, f,
                      indent=1)
        break
    time.sleep(120)
