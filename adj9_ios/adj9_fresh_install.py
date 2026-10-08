"""FRESH INSTALL — penti-iOS (jut9tib0eeps), fully signed with the solved claims law.

Fresh idfv, installed-this-minute story, att_status=0 (the capture-faithful profile
-> the "No User Consent" non-organic state per the user's rule), analytics host.
Flow: signed /session -> signed /attribution (8s later) — the capture's sequence.
"""
import time, base64, sys, os, json, uuid
from datetime import datetime, timedelta
from urllib.parse import urlencode
from curl_cffi import requests as cr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj9_signature as sg
import adj9_claims_law as law

APP_TOKEN = "jut9tib0eeps"
BUNDLE = "com.penti.PentiApp"
UA = "Penti/8 CFNetwork/3860.600.12 Darwin/25.5.0"
SDK = "ios5.8.0"
ADJ_V = "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"
DEVICE_NAME = "iPhone12,1"
OS_VERSION = "26.5"
HOST = "https://analytics.adjust.com"      # att_status=0 pipeline
S = cr.Session(impersonate="safari17_0")
now = datetime.utcnow() - timedelta(hours=3)


def fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond//1000:03d}Z+0300"


def signed(method, path, params, kind):
    t = int(time.time()) + 1
    while time.time() < t:
        time.sleep(0.02)
    p = dict(params)
    p["created_at"] = p["sent_at"] = fmt(datetime.utcfromtimestamp(t - 3 * 3600))
    claims = law.build_claims(p, kind, ADJ_V)[0].encode("latin1")
    blob = sg.mint_ios(kind, p, unix_sec=t, claims=claims,
                       device_name=DEVICE_NAME, os_name="ios", client_sdk=SDK)[0]
    auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), ADJ_V))
    h = {"User-Agent": UA, "Client-Sdk": SDK, "Authorization": auth}
    if method == "POST":
        h["Content-Type"] = "application/x-www-form-urlencoded"
        return S.post(HOST + path, data=p, headers=h, timeout=30)
    return S.get(HOST + path + "?" + urlencode(p), headers=h, timeout=30)


idfv = str(uuid.uuid4()).upper()
dedupe = str(uuid.uuid4()).upper()
fb = "XZ" + str(uuid.uuid4()).upper()
installed = fmt(now - timedelta(minutes=1))
started = fmt(now - timedelta(minutes=1))
print("FRESH idfv:", idfv, flush=True)

base = {"bundle_id": BUNDLE, "app_token": APP_TOKEN,
        "app_version": "8", "app_version_short": "2.35.0",
        "device_name": DEVICE_NAME, "device_type": "iPhone",
        "os_name": "ios", "os_version": OS_VERSION, "environment": "production",
        "idfv": idfv, "att_status": "0", "tracking_enabled": "0",
        "fb_anon_id": fb, "primary_dedupe_token": dedupe,
        "needs_response_details": "1", "attribution_deeplink": "1",
        "installed_at": installed, "started_at": started,
        "session_count": "1", "foreground": "1",
        "send_in_background_enabled": "0", "enqueue_size": "0",
        "offline_mode_enabled": "0", "retry_count": "0"}

print("\n[1] /session (signed, solved claims) ...", flush=True)
r = signed("POST", "/session", base, "session")
print("[session]", r.status_code, "|", r.text[:200], flush=True)
adid = r.json().get("adid") if r.status_code == 200 and r.text.startswith("{") else None
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
    print("    tracker:", tk, "|", name, "| reattr:", a.get("is_reattributed"), flush=True)
    if "No User Consent" in name:
        print("\nVERDICT: NON-ORGANIC — fresh install landed in the 'No User Consent' state", flush=True)
    elif name == "Organic":
        print("\nVERDICT: Organic — fresh install shows organic (consented naming)")
    else:
        print("\nVERDICT: BOOKED —", tk, "/", name, flush=True)
except Exception:
    print("    body:", r.text[:300])
json.dump({"idfv": idfv, "adid": adid, "resp": r.text[:500]},
          open(os.path.join(os.path.dirname(__file__), "adj9_fresh_install_result.json"), "w"),
          indent=1)