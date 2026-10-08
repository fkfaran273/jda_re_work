"""deferred_watch.py — re-ask the moto install's attribution after the
deferred window (ask_in ~1.76 h from 15:25 => from ~17:11), then hourly.
Writes deferred_verdict.json on the first 200.  Runs in the background.

    python deferred_watch.py   (nohup-style: run via the Bash background)
"""
import json
import sys
import time
import urllib.parse
from datetime import datetime

sys.path.insert(0, "..")
sys.path.insert(0, ".")
import adj7_pure as sg
from curl_cffi import requests as cr

calls = json.load(open("fresh_install_maps.json"))
attr = next(c for c in calls if c["n"] == 3)
CERT = "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"
sg.CERT_SHA1 = CERT
sg.CLIENT_SDK = "android5.6.0"

FIELDS = dict(attr["arg1"])
for k in ("adj_signing_id", "algorithm", "headers_id", "native_version",
          "endpoint"):
    FIELDS.pop(k, None)

WAIT_S = int(sys.argv[1]) if len(sys.argv) > 1 else 6300
print("[%s] sleeping %d s before the re-ask..." % (
    datetime.now().strftime("%H:%M:%S"), WAIT_S), flush=True)
time.sleep(WAIT_S)

for attempt in range(1, 9):
    now = time.time()
    stamp = (datetime.utcfromtimestamp(now + 19800)
             .strftime("%Y-%m-%dT%H:%M:%S.")
             + "%03d" % (int(now * 1000) % 1000) + "Z+0530")
    f = dict(FIELDS)
    f["created_at"] = stamp
    f["sent_at"] = stamp
    auth = sg.mint_adj7("attribution", f, unix_sec=int(now),
                        client_sdk="android5.6.0", include_block2=True)
    r = cr.get("https://app.adjust.com/attribution?" + urllib.parse.urlencode(f),
               headers={"Client-SDK": "android5.6.0",
                        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; "
                                      "moto g42 Build/S2SE32.28-28-4)",
                        "Authorization": auth,
                        "Accept-Encoding": "gzip"}, timeout=30)
    verdict = ("PENDING" if r.status_code != 200 else
               ("NON-ORGANIC" if '"network":"Organic"' not in r.text
                else "Organic"))
    print("[%s] re-ask #%d -> HTTP %d  %s  %s" % (
        datetime.now().strftime("%H:%M:%S"), attempt, r.status_code, verdict,
        r.text[:200]), flush=True)
    if r.status_code == 200 and '"attribution"' in r.text:
        with open("deferred_verdict.json", "w") as f:
            json.dump({"attempt": attempt, "verdict": verdict,
                       "body": r.text}, f, indent=1)
        print("verdict saved", flush=True)
        break
    time.sleep(1800)
