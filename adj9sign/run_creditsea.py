"""run_creditsea.py — the adj9 funnel for com.creditsea.app (via mobpine link).

    1. edit DEVICE_JSON (any device-info dump) and LINK below
    2. python run_simple.py

That's it. The flow reads top to bottom:

    click -> /session -> /sdk_click -> /attribution -> verdict

Every request is signed fresh by signer_simple (own claims, own second,
own seed). Deps: capstone, curl-cffi.  Takes ~1-2 min.
"""
import datetime
import json
import os
import sys
import time
import re
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# =========================================================================
# EDIT THESE TWO
# =========================================================================
DEVICE_JSON = "device_g64.json"   # any device-info dump (GAID inside)
LINK = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_"
        + time.strftime("%m%d") + "&creative=penti_generic")
# =========================================================================

import signer_simple as sg  # noqa: E402
from signer_simple import auth_header  # noqa: E402

# --- creditsea app-specific (appdiff checklist) -----------------------
sg.DESC9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")  # its cert
CRED_PACKAGE = "com.creditsea.app"
CRED_VERSION = "1.0.174"

# --- the PROVEN 5.8.0 claims law (desc10_58, validated 3/3 byte-exact) --
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "adj9", "rev", "creditsea"))
import desc10_58  # noqa: E402

# the device signs client_sdk as the Flutter composite (from the captured map),
# while the Client-SDK header stays the plain SDK version
CRED_CLIENT_SDK = "flutter5.8.0@android5.8.0"

_orig_claims_58 = desc10_58.claims_for_law_58


def claims_58_creditsea(val, kind):
    v = dict(val)
    v["client_sdk"] = CRED_CLIENT_SDK
    return _orig_claims_58(v, kind)


sg.claims_for_law = claims_58_creditsea   # sign_request reads this global

APP_TOKEN = "i2n2e5kmcpvk"
CLIENT_SDK = "flutter5.8.0@android5.8.0"               # the Client-SDK header value


def load_device(path):
    """The AUTHENTIC creditsea device profile — the captured g42 signing map
    (adj9_cap_fresh.log sign_input), identity-adjusted per run: fresh GAID +
    android_uuid, fresh created_at/sent_at, install story 9d/2d ago."""
    import datetime

    def stamp(ts, ms):
        dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
              + datetime.timedelta(minutes=330))
        return dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms + "Z+0530")

    now = time.time()
    # the CLEAN-SHOT identity: a fresh GAID, exactly one click, realistic timing
    gaid = str(uuid.uuid4())
    params = {
        "app_token": APP_TOKEN,
        "gps_adid": gaid,
        "android_uuid": str(uuid.uuid4()),
        "api_level": "31",
        "app_version": CRED_VERSION,
        "attribution_deeplink": "1",
        "client_sdk": CRED_CLIENT_SDK,
        "connectivity_type": "1",
        "country": "IN",
        "cpu_type": "arm64-v8a",
        "created_at": stamp(time.time() - 25, 761),
        "device_manufacturer": "motorola",
        "device_name": "moto g42",
        "device_type": "phone",
        "display_height": "2237",
        "display_width": "1080",
        "enqueue_size": "0",
        "environment": "production",
        "first_error": "0",
        "foreground": "1",
        "gps_adid_attempt": "1",
        "gps_adid_src": "service",
        "hardware_name": "S2SE32.28-28-4",
        "initiating_package_name": "com.android.vending",
        "installed_at": stamp(now - 9 * 86400, 560),
        "language": "en",
        "last_error": "0",
        "needs_response_details": "1",
        "offline_mode_enabled": "0",
        "os_build": "S2SE32.28-28-4",
        "os_name": "android",
        "os_version": "12",
        "package_name": CRED_PACKAGE,
        "retry_count": "0",
        "screen_density": "high",
        "screen_format": "long",
        "screen_size": "normal",
        "sent_at": stamp(time.time() - 25, 768),
        "session_count": "1",
        "session_length": "0",
        "store_name_from_system": "com.android.vending",
        "subsession_count": "1",
        "time_spent": "0",
        "tracking_enabled": "1",
        "ui_mode": "1",
        "updated_at": stamp(now - 2 * 86400, 560),
        "wait_time": "0.0",
        "wait_total": "0.0",
    }
    chrome_ua = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36")
    dalvik_ua = ("Dalvik/2.1.0 (Linux; U; Android 12; moto g42 "
                 "Build/S2SE32.28-28-4)")
    return gaid, params, chrome_ua, dalvik_ua, stamp
    return gaid, params, chrome_ua, dalvik_ua, stamp


MOBPINE = ("http://clicks.mobpine.com/api/track/v1/click"
           "?aff_id=3&offer_id=23482250")
#  http://clicks.mobpine.com/api/track/v1/click?aff_id=3&offer_id=23482250

def click(gaid, chrome_ua):
    """Two-hop click: mobpine -> creditsea.go.link (bind GAID) -> referrer."""
    from curl_cffi import requests as cr
    s = cr.Session(impersonate="chrome131")
    r = s.get(MOBPINE, headers={"User-Agent": chrome_ua},
              allow_redirects=False, timeout=30)
    golink = r.headers.get("Location", "")
    print("[RUN] hop0 %d -> %s" % (r.status_code, golink[:100]), flush=True)
    if not golink:
        return None
    golink += ("&adj_gps_adid=" + gaid + "&adj_idfa=" + gaid
               + "&adj_click_id=" + gaid)
    r = s.get(golink, headers={"User-Agent": chrome_ua},
              allow_redirects=False, timeout=30)
    loc = r.headers.get("Location", "")
    referrer = None
    if "adjust_reftag" in loc:
        m = re.search(r"adjust_reftag(?:%3D|=)([A-Za-z0-9]+)", loc)
        referrer = "adjust_reftag=" + m.group(1) if m else None
    print("[RUN] hop1 %d referrer=%s"
          % (r.status_code, (referrer or "NONE")[:60]), flush=True)
    print("[RUN] using our own click's referrer:", referrer, flush=True)
    return referrer


def send(path, params, kind, ua, method="POST"):
    """Sign THIS request (own claims/second/seed) and call the endpoint."""
    import http.client
    auth = auth_header(sg.sign_request(params, kind)[0])
    body = urllib.parse.urlencode(params).encode()
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    conn.putrequest(method, path + (("" if method == "POST" else "?"
                                     + urllib.parse.urlencode(params))),
                    skip_host=1, skip_accept_encoding=1)
    conn.putheader("Client-SDK", CLIENT_SDK)   # mandatory on EVERY call
    conn.putheader("Authorization", auth)
    conn.putheader("User-Agent", ua)
    conn.putheader("Host", "app.adjust.com")
    if method == "POST":
        conn.putheader("Content-Type", "application/x-www-form-urlencoded")
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body if method == "POST" else None)
    resp = conn.getresponse()
    out = resp.read().decode("utf-8", "replace")
    conn.close()
    print("[RUN] %-12s %d %s" % (kind, resp.status, out[:110]), flush=True)
    return resp.status, out


def main():
    print("[RUN] device json: %s" % DEVICE_JSON, flush=True)
    gaid, params, chrome_ua, dalvik_ua, stamp = load_device(DEVICE_JSON)
    print("[RUN] gaid=%s" % (gaid or "NONE (control mode, expect Organic)"),
          flush=True)

    t_click = time.time()
    referrer = click(gaid, chrome_ua)
    if not referrer:
        return 1

    # ---- /session: the identity arrives -------------------------------
    # the Play install timeline: click → install begins (+5s) → install
    # completes (+14s = installed_at) → the app opens → the session
    time.sleep(14)
    session = dict(params)
    session["installed_at"] = stamp(t_click + 14, 560)   # AFTER the click ✓
    session["updated_at"] = stamp(t_click + 14, 560)     # AFTER the click ✓
    session.update({"session_count": "1", "session_length": "0",
                    "time_spent": "0", "subsession_count": "1",
                    "created_at": stamp(t_click + 20, 61),
                    "sent_at": stamp(t_click + 20, 68)})
    code, _ = send("/session", session, "session", dalvik_ua)
    if code != 200:
        return 1

    # ---- /sdk_click: the click joins the device -----------------------
    time.sleep(3)
    cp = {k: v for k, v in session.items()
          if k not in ("first_error", "last_error", "retry_count")}
    cp["installed_at"] = stamp(t_click + 14, 560)   # AFTER the click ✓
    cp["updated_at"] = stamp(t_click + 14, 560)     # AFTER the click ✓
    cp.update({"source": "install_referrer", "referrer_api": "google",
               "referrer": referrer, "google_play_instant": "0",
               "install_version": session["app_version"],
               "created_at": stamp(t_click + 20, 24),
               "sent_at": stamp(t_click + 20, 31),
               "click_time": stamp(t_click, 0),
               "click_time_server": stamp(t_click - 2, 0),
               "install_begin_time": stamp(t_click + 6, 0),
               "install_begin_time_server": stamp(t_click + 4, 0),
               "activity_kind": "click"})
    code, _ = send("/sdk_click", cp, "click", dalvik_ua)
    if code != 200:
        return 1

    # ---- /attribution: the verdict -------------------------------------
    time.sleep(3)
    ap = {"app_token": APP_TOKEN, "gps_adid": gaid,
          "android_uuid": session["android_uuid"],
          "activity_kind": "attribution", "initiated_by": "sdk",
          "needs_response_details": "1", "environment": "production",
          "api_level": params["api_level"],
          "app_version": params["app_version"],
          "created_at": stamp(time.time(), 77),
          "device_name": params["device_name"],
          "device_type": params["device_type"],
          "gps_adid_src": params["gps_adid_src"], "os_name": "android",
          "os_version": params["os_version"],
          "package_name": params["package_name"], "tracking_enabled": "1"}
    code, body = send("/attribution", ap, "attribution", dalvik_ua,
                      method="GET")

    # ---- verdict --------------------------------------------------------
    print("=" * 60)
    try:
        att = json.loads(body).get("attribution") or {}
    except Exception:
        att = {}
    if att.get("network") and att["network"] != "Organic":
        print("*** NON-ORGANIC: %s | %s | reattr=%s ***"
              % (att["network"], att.get("tracker_name"),
                 att.get("is_reattributed")))
        return 0
    print("*** Organic / not joined: %s" % body[:150])
    return 1


if __name__ == "__main__":
    sys.exit(main())
