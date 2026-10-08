"""adj9 iOS manual runner — penti-ios (app_token jut9tib0eeps) funnel, SIGNED.

Two-file pair (manual_run pattern):
    adj9_signature.py    <- the adj9-iOS signer (mint_ios; emu-free, pure Python)
    adj9_run_install.py  <- THIS file: click -> session -> sdk_click -> attribution

Verified 2026-10-05 against pentiiosauto_ct_logs_5oct_ios11.chls:
  - header law (MINSTD, seed=signing second) inverted at offset 0 on the capture
  - replay acceptance: our signature returned the IDENTICAL server response as
    the real captured signature (same tracker/state); corrupted control identical too
Config below. Fresh idfv/dedupe per run; IDFA configurable.
"""
import time, uuid, sys, os, base64
from datetime import datetime, timedelta
from urllib.parse import urlencode
from curl_cffi import requests as cr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj9_signature as sg
import adj9_claims_law as law

ADJ_V = "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"   # ios-simulator service constant
# real-device value: sg.make_adj_verification("ios") = KlcAG2cbAAsKSl1KXiwSSjA=

# ============================ CONFIG =====================================
LINK       = "https://app.adjust.com/<tracker>?campaign=X&adgroup=Y&idfa=<idfa>"
APP_TOKEN  = "jut9tib0eeps"
BUNDLE     = ""            # e.g. the app's bundle id (from the capture)
CLIENT_SDK = "ios5.8.0"
UA         = "hunch/3 CFNetwork/1410.1 Darwin/22.6.0"   # app UA from the capture
CLICK_UA   = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1")
IDFA       = ""            # "" = fresh random; att_status=3 pipeline uses it
ATT_STATUS = "3"           # 3 -> consent.adjust.com; 0 -> analytics.adjust.com
ASA_TOKEN  = ""            # optional: fresh AdServices attribution_token (service run)
OS_VERSION = "26.5"
DEVICE_NAME = "iPhone12,1"
# =========================================================================

S = cr.Session(impersonate="safari17_0")
now = datetime.utcnow() - timedelta(hours=3)


def fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond//1000:03d}Z+0300"


def host_for(att):
    return "https://consent.adjust.com" if att == "3" else "https://analytics.adjust.com"


def signed_call(method, path, params, kind, att=ATT_STATUS, lead=10):
    """adj9-iOS signatures are pure Python (~ms). Mint at send time with the
    SOLVED claims law (the server verifies the claims envelope: wrong claims ->
    silent Organic fallback; solved claims -> the real attribution path)."""
    t_send = int(time.time())
    p = dict(params)
    p["created_at"] = p["sent_at"] = fmt(datetime.utcfromtimestamp(t_send - 3 * 3600))
    claims = law.build_claims(p, kind, ADJ_V)[0].encode("latin1")
    blob, auth = sg.mint_ios(kind, p, unix_sec=t_send, claims=claims,
                             device_name=DEVICE_NAME, client_sdk=CLIENT_SDK)
    auth = ("Signature signature=\"%s\",adj_signing_id=\"1500000\",algorithm=\"adj9\","
            "headers_id=\"10\",native_version=\"5.0.0\",adj_verification=\"%s\""
            % (base64.b64encode(blob).decode(), sg.make_adj_verification("ios")))
    h = {"User-Agent": UA, "Client-Sdk": CLIENT_SDK, "Authorization": auth}
    if method == "POST":
        h["Content-Type"] = "application/x-www-form-urlencoded"
        return S.post(host_for(att) + path, data=p, headers=h, timeout=30)
    return S.get(host_for(att) + path + "?" + urlencode(p), headers=h, timeout=30)


def main():
    idfa = IDFA.strip() or str(uuid.uuid4()).upper()
    idfv = str(uuid.uuid4()).upper()
    dedupe = str(uuid.uuid4()).upper()
    fb = "XZ" + str(uuid.uuid4()).upper()
    installed = fmt(now - timedelta(days=7))
    started = fmt(now - timedelta(days=15))
    print("idfa:", idfa, "\nidfv:", idfv)

    # 1. click (idfa= is Adjust's documented matching param; one click only)
    click_link = LINK + ("&" if "?" in LINK else "?") + "idfa=" + idfa
    r = S.get(click_link, headers={"User-Agent": CLICK_UA}, timeout=30, allow_redirects=True)
    print("[click]", r.status_code, flush=True)
    time.sleep(60)

    base = {"bundle_id": BUNDLE, "app_token": APP_TOKEN,
            "app_version": "3", "app_version_short": "3.0.1",
            "device_name": DEVICE_NAME, "device_type": "iPhone",
            "os_name": "ios", "os_version": OS_VERSION, "environment": "production",
            "idfa": idfa, "idfv": idfv, "att_status": ATT_STATUS,
            "tracking_enabled": "1" if ATT_STATUS == "3" else "0",
            "fb_anon_id": fb, "primary_dedupe_token": dedupe,
            "needs_response_details": "1", "attribution_deeplink": "1",
            "installed_at": installed, "started_at": started,
            "session_count": "1", "foreground": "1",
            "send_in_background_enabled": "0", "enqueue_size": "0",
            "offline_mode_enabled": "0"}

    # 2. /session (signed)
    r = signed_call("POST", "/session", base, "session")
    print("[session]", r.status_code, "|", r.text[:180], flush=True)
    adid = r.json().get("adid") if r.status_code == 200 and r.text.startswith("{") else None
    print("    adid:", adid, flush=True)
    time.sleep(5)

    # 3. /sdk_click (signed; apple_ads shape when ASA_TOKEN provided)
    cp = {k: v for k, v in base.items() if k not in ("session_count", "enqueue_size")}
    cp["click_time"] = fmt(datetime.utcnow() - timedelta(hours=1))
    if ASA_TOKEN:
        cp["source"] = "apple_ads"
        cp["attribution_token"] = ASA_TOKEN
    r = signed_call("POST", "/sdk_click", cp, "click")
    print("[sdk_click]", r.status_code, "|", r.text[:180], flush=True)
    time.sleep(5)

    # 4. /attribution (signed)
    ap = {k: v for k, v in base.items()
          if k not in ("session_count", "enqueue_size", "foreground",
                       "send_in_background_enabled", "offline_mode_enabled")}
    ap["initiated_by"] = "backend"
    r = signed_call("GET", "/attribution", ap, "attribution")
    print("[attribution]", r.status_code, flush=True)
    try:
        a = r.json().get("attribution", {})
        tk, name = a.get("tracker_token", ""), a.get("tracker_name", "")
        eng = a.get("engagement_time", "")
        print("    tracker:", tk, "|", name, "| engagement:", eng,
              "| reattr:", a.get("is_reattributed"))
        if name.lower() == "organic":
            print("\nVERDICT: ORGANIC")
        elif tk == "unattr" or "consent" in name.lower():
            print("\nVERDICT: NON-ORGANIC STATE —", name, "(engagement)" if eng else "")
        else:
            print("\nVERDICT: BOOKED —", tk, "/", name)
    except Exception:
        print("    body:", r.text[:300])

    json.dump({"idfa": idfa, "idfv": idfv, "adid": adid,
               "attribution": r.text[:500] if r else None},
              open(os.path.join(os.path.dirname(__file__), "adj9_run_result.json"), "w"),
              indent=1)


if __name__ == "__main__":
    main()