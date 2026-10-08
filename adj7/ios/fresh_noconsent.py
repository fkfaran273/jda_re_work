# -*- coding: utf-8 -*-
"""fresh_noconsent.py -- the adj9_fresh_install.py PASS shape, ported to the
adj7 / nirio iOS campaign with OUR adj7_ios_pure signer.

The 07-Oct Run A (run_install_ios.py with FUNNEL_ATT_STATUS=0) answered
"Organic (consented naming)" because the map was still the att-3 profile:
it carried IDFA, had no tracking_enabled / fb_anon_id, created_at !=
sent_at, and went out on python-requests TLS.  The adj9 pass
(adj9_fresh_install.py, 2026-10-05, "unattr / No User Consent") differs:

  * NO idfa at all (fresh device keyed on idfv + fb_anon_id)
  * att_status=0 AND tracking_enabled=0
  * fb_anon_id present ("XZ" + uuid upper)
  * created_at == sent_at, installed/started 1 min ago
  * curl_cffi safari17_0 TLS, analytics.adjust.com
  * click-less: signed /session -> 8 s -> signed /attribution

Run:  python fresh_noconsent.py
"""
import base64
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlencode

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import adj7_ios_pure as sg          # noqa: E402
from curl_cffi import requests as cr  # noqa: E402

APP_TOKEN = "cv4d2hlazp4w"
BUNDLE = "com.fdjservices.nirio"
UA = "Nirio/494 CFNetwork/1410.1 Darwin/22.6.0"
SDK = "react-native5.4.4@ios5.4.6"
DEVICE_NAME = "iPhone10,1"
OS_VERSION = "16.7.16"
HOST = "https://analytics.adjust.com"      # att_status=0 pipeline

S = cr.Session(impersonate="safari17_0")
now = datetime.utcnow() - timedelta(hours=3)


def fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0300" % (
        dt.microsecond // 1000)


def signed(method, path, params, kind):
    t = int(time.time()) + 1
    while time.time() < t:
        time.sleep(0.02)
    p = dict(params)
    p["created_at"] = p["sent_at"] = fmt(
        datetime.utcfromtimestamp(t - 3 * 3600))
    auth, blob = sg.sign_request(p, kind, second=t, client_sdk=SDK)
    if method == "POST":
        h = {"User-Agent": UA, "Client-Sdk": SDK, "Authorization": auth,
             "Content-Type": "application/x-www-form-urlencoded"}
        return S.post(HOST + path, data=p, headers=h, timeout=30)
    return S.get(HOST + path + "?" + urlencode(p),
                 headers={"User-Agent": UA, "Client-Sdk": SDK,
                          "Authorization": auth}, timeout=30)


idfv = str(uuid.uuid4()).upper()
dedupe = str(uuid.uuid4()).upper()
fb = "XZ" + str(uuid.uuid4()).upper()
installed = fmt(now - timedelta(minutes=1))
started = fmt(now - timedelta(minutes=1))
print("FRESH idfv:", idfv, flush=True)

base = {"bundle_id": BUNDLE, "app_token": APP_TOKEN,
        "app_version": "494", "app_version_short": "16.4.6",
        "device_name": DEVICE_NAME, "device_type": "iPhone",
        "os_name": "ios", "os_version": OS_VERSION,
        "environment": "production",
        "idfv": idfv, "att_status": "0", "tracking_enabled": "0",
        "fb_anon_id": fb, "primary_dedupe_token": dedupe,
        "needs_response_details": "1", "attribution_deeplink": "1",
        "installed_at": installed, "started_at": started,
        "session_count": "1", "foreground": "1",
        "send_in_background_enabled": "0", "enqueue_size": "0",
        "offline_mode_enabled": "0", "retry_count": "0"}

print("\n[1] /session (signed, adj7 claims) ...", flush=True)
r = signed("POST", "/session", base, "session")
print("[session]", r.status_code, "|", r.text[:200], flush=True)
adid = (r.json().get("adid")
        if r.status_code == 200 and r.text.startswith("{") else None)
print("    adid:", adid, flush=True)
time.sleep(8)

print("\n[2] /attribution (signed) ...", flush=True)
ap = {k: v for k, v in base.items()
      if k not in ("session_count", "enqueue_size", "foreground",
                   "send_in_background_enabled", "offline_mode_enabled",
                   "retry_count")}
ap["initiated_by"] = "backend"
r = signed("GET", "/attribution", ap, "attribution")
print("[attribution]", r.status_code, flush=True)
try:
    a = r.json().get("attribution", {})
    tk, name = a.get("tracker_token", ""), a.get("tracker_name", "")
    print("    tracker:", tk, "|", name,
          "| reattr:", a.get("is_reattributed"), flush=True)
    if "No User Consent" in name:
        print("\nVERDICT: NON-ORGANIC -- 'No User Consent' state reached "
              "with OUR adj7 signature", flush=True)
    elif name == "Organic":
        print("\nVERDICT: Organic (consented naming; unattributed)",
              flush=True)
    else:
        print("\nVERDICT: BOOKED --", tk, "/", name, flush=True)
except Exception:
    print("    body:", r.text[:300])

json.dump({"idfv": idfv, "adid": adid, "resp": r.text[:500]},
          open(os.path.join(HERE, "fresh_noconsent_result.json"), "w"),
          indent=1)
