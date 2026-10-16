# -*- coding: utf-8 -*-
"""hunch_fresh_noconsent.py -- the adj9_fresh_install.py shape, ported to
hunch + the adj7ios signer.

The adj9-ios proof (2026-10-05, PENTI) landed the logged non-organic
state ("No User Consent") with: att0 + tracking_enabled=0 + no idfa +
curl_cffi safari17_0 TLS + session -> 8 s -> attribution
(initiated_by=backend, session-only fields stripped), NO sdk_click, NO
click.  Same shape here, signed adj7 (headers_id 8 / native 3.62.0 /
flutter5.5.0@ios5.5.0):
"""
import base64
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlencode

from curl_cffi import requests as cr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj7ios_pure as sg                                   # noqa: E402

APP_TOKEN = "vf3lochhmgw0"
BUNDLE = "social.hunch.app"
UA = "hunch/3 CFNetwork/1410.1 Darwin/22.6.0"
SDK = "flutter5.5.0@ios5.5.0"
DEVICE_NAME = "iPhone10,1"
OS_VERSION = "16.7.15"
HOST = "https://analytics.adjust.com"      # att0 pipeline
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
    auth, _ = sg.sign_request(p, kind, client_sdk=SDK, headers_id="8",
                              native_version="3.62.0")
    h = {"User-Agent": UA, "Client-Sdk": SDK, "Authorization": auth}
    if method == "POST":
        h["Content-Type"] = "application/x-www-form-urlencoded"
        return S.post(HOST + path, data=p, headers=h, timeout=30)
    return S.get(HOST + path + "?" + urlencode(p), headers=h, timeout=30)


def main():
    idfv = str(uuid.uuid4()).upper()
    dedupe = str(uuid.uuid4()).upper()
    fb = "XZ" + str(uuid.uuid4()).upper()
    installed = fmt(now - timedelta(minutes=1))
    started = fmt(now - timedelta(minutes=1))
    print("FRESH idfv:", idfv, flush=True)

    base = {"bundle_id": BUNDLE, "app_token": APP_TOKEN,
            "app_version": "3", "app_version_short": "3.0.1",
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

    print("\n[1] /session (signed adj7ios, safari TLS) ...", flush=True)
    r = signed("POST", "/session", base, "session")
    print("[session]", r.status_code, "|", r.text[:200], flush=True)
    adid = r.json().get("adid") if r.status_code == 200 else None
    time.sleep(8)

    print("\n[2] /attribution (signed, 8 s later) ...", flush=True)
    ap = {k: v for k, v in base.items()
          if k not in ("session_count", "enqueue_size", "foreground",
                       "send_in_background_enabled", "offline_mode_enabled",
                       "retry_count")}
    ap["initiated_by"] = "backend"
    r = signed("GET", "/attribution", ap, "attribution")
    print("[attribution]", r.status_code, flush=True)
    verdict = "?"
    try:
        a = r.json().get("attribution", {})
        print("    tracker:", a.get("tracker_token"), "|",
              a.get("tracker_name"), "| network:", a.get("network"),
              "| reattr:", a.get("is_reattributed"), flush=True)
        name = a.get("tracker_name", "")
        if "No User Consent" in name:
            verdict = "NO USER CONSENT -- logged verdict state reproduced"
        elif name == "Organic":
            verdict = "Organic"
        else:
            verdict = "BOOKED %s" % a.get("tracker_token")
    except Exception:                                       # noqa: BLE001
        print("    body:", r.text[:300], flush=True)
    print("\nVERDICT:", verdict, flush=True)
    json.dump({"idfv": idfv, "adid": adid, "resp": r.text[:600],
               "verdict": verdict},
              open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "hunch_fresh_noconsent_result.json"),
                   "w"), indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
