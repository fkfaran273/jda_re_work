"""creditsea_bd_funnel.py -- the decisive creditsea conversion funnel.

The EXACT user-provided go.link template (BD / BD9 / SC_898989qm) WITH the
S2S postback callbacks (adj_install_callback + adj_event_callback_78v7mj)
that were missing from every previous attempt:

    click (curl_cffi chrome131, fresh GAID in {click_id}/{sub3})
      -> wait ~14s (Play install timing)
      -> POST /session    (installed_at/updated_at AFTER the click)
      -> wait ~3s
      -> POST /sdk_click  (adjust_reftag from our own click's redirect)
      -> wait ~5s
      -> GET  /attribution  -> verdict

Signing: signer_simple + the proven 5.8.0 claims law (desc10_58, 192/192
byte-exact against 3 genuine device signings), creditsea's own cert D9,
head phase (0x2b,) -- passed EXPLICITLY to sign_request (note:
`sg.WIN_PHASE = ...` alone is an inert no-op because the `head` default
argument was bound at def time; every previous runner signed with penti's
(0x2b, 0x48) despite "setting" the creditsea phase).
Client-SDK header: flutter5.8.0@android5.8.0 on EVERY request (the Flutter
composite -- sign_request overwrites the claim, so the claims law wrapper
re-forces it).

Wire shapes: the GOLD maps (adj9/rev/creditsea/desc10_58._gold_maps),
which is the exact genuine moto g42 map set the law validated byte-exact
against -- session 46 wire keys / click 50 / attribution 24, with only the
identity (gps_adid, android_uuid) and timing swapped.  initiated_by is the
genuine "backend" for attribution.

Transport: adj9/rev/okhttp_transport.OkHttpTransport (uTLS Conscrypt hello,
OkHttp header order, FormBody %20 encoding, one keep-alive connection for
the whole flow) with the Client-SDK header overridden to the Flutter
composite and its authentic moto g42 Dalvik UA.

Deps: curl-cffi, tls_client, capstone.  ~2-3 min (3 VM signings).
"""
import datetime
import json
import os
import re
import sys
import time
import traceback
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.join(os.path.dirname(HERE), "adj9", "rev")
sys.path.insert(0, HERE)
sys.path.insert(0, REV)

import signer_simple as sg                      # noqa: E402
from okhttp_transport import OkHttpTransport    # noqa: E402

# =========================================================================
# creditsea app constants (the proven creditsea 5.8.0 config)
# =========================================================================
sg.DESC9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")  # its cert
HEAD = (0x2B,)                       # creditsea per-app d0 head (penti=(2b,48))
APP_TOKEN = "i2n2e5kmcpvk"
CLIENT_SDK = "flutter5.8.0@android5.8.0"             # the Flutter composite
ORGANIC_TOKEN = "221wahrq"

# --- the PROVEN 5.8.0 claims law, forced to the Flutter composite --------
sys.path.insert(0, os.path.join(REV, "creditsea"))
import desc10_58                                 # noqa: E402

_orig_claims_58 = desc10_58.claims_for_law_58


def claims_58_creditsea(val, kind):
    # sign_request overwrites client_sdk with the module constant
    # (penti's android5.7.0) -- re-force the genuine Flutter composite.
    v = dict(val)
    v["client_sdk"] = CLIENT_SDK
    return _orig_claims_58(v, kind)


sg.claims_for_law = claims_58_creditsea          # sign_request reads this global


def sign(params, kind):
    """One fresh signing with creditsea's own head phase -- EXPLICITLY."""
    blob, second, info = sg.sign_request(params, kind, head=HEAD)
    return sg.auth_header(blob), second, info


# =========================================================================
# THE EXACT USER LINK TEMPLATE (macros replaced with one fresh GAID)
# =========================================================================
LINK_TEMPLATE = (
    "https://creditsea.go.link?adj_t=246drhkt&adj_campaign=BD"
    "&adj_adgroup=BD9&adj_creative=SC_898989qm"
    "&adj_click_id={click_id}&adj_gps_adid={sub3}"
    "&adj_install_callback="
    "http%3A%2F%2Fclick.quasarmobi.com%2Fapi%2Ftrack%2Fv1%2Fpostback"
    "%3Fclick_id%3D{click_id}%26offer_id%3Dsmartsea"
    "%26advertiser_id%3Dsmartconnect%26p_sub1%3Dadjust"
    "&adj_event_callback_78v7mj="
    "http%3A%2F%2Fclick.quasarmobi.com%2Fapi%2Ftrack%2Fv1%2Fevents"
    "%3Fclick_id%3D{click_id}%26goal%3D%7Bevent%7D%26offer_id%3Dsmartsea"
    "%26advertiser_id%3Dsmartconnect%26p_sub1%3Dadjust"
)

CHROME_UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36")


def stamp(ts, ms):
    """The genuine creditsea timestamp literal: IST wall time + 'Z+0530'."""
    dt = (datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc)
          + datetime.timedelta(minutes=330))
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % ms + "Z+0530"


# =========================================================================
# 1. THE CLICK
# =========================================================================
def fire_click(link):
    """Browser click (chrome131), following the redirect chain by hand until
    the adjust_reftag shows up (it rides the Play referrer)."""
    from curl_cffi import requests as cr
    s = cr.Session(impersonate="chrome131")
    url = link
    hops = []
    reftag = None
    for i in range(10):
        r = s.get(url, headers={"User-Agent": CHROME_UA},
                  allow_redirects=False, timeout=30)
        loc = r.headers.get("Location", "")
        hops.append({"hop": i + 1, "status": r.status_code, "url": url,
                     "location": loc})
        print("[click] hop%d %d %s" % (i + 1, r.status_code, url[:110]),
              flush=True)
        if loc:
            print("[click]       -> %s" % loc[:160], flush=True)
        m = (re.search(r"adjust_reftag(?:%3D|=)([A-Za-z0-9]+)", loc)
             or re.search(r"adjust_reftag(?:%3D|=)([A-Za-z0-9]+)",
                          r.text[:4000]))
        if m:
            reftag = m.group(1)
            print("[click] adjust_reftag found: %s" % reftag, flush=True)
            break
        if not loc:
            body = (r.text or "")[:300].replace("\n", " ")
            print("[click] no more redirects; body: %s" % body, flush=True)
            break
        url = urllib.parse.urljoin(url, loc)
    return hops, reftag


# =========================================================================
# THE WIRE SHAPES -- the GOLD maps, identity/timing swapped
# =========================================================================
def session_params(gaid, android_uuid, t_click, ins_at):
    t = time.time()
    return {
        "activity_kind": "session",
        "android_uuid": android_uuid,
        "api_level": "31",
        "app_token": APP_TOKEN,
        "app_version": "1.0.174",
        "attribution_deeplink": "1",
        "client_sdk": CLIENT_SDK,
        "connectivity_type": "1",
        "country": "IN",
        "cpu_type": "arm64-v8a",
        "created_at": stamp(t, 928),
        "device_manufacturer": "motorola",
        "device_name": "moto g42",
        "device_type": "phone",
        "display_height": "2237",
        "display_width": "1080",
        "enqueue_size": "0",
        "environment": "production",
        "first_error": "0",
        "foreground": "1",
        "gps_adid": gaid,
        "gps_adid_attempt": "1",
        "gps_adid_src": "service",
        "hardware_name": "S2SE32.28-28-4",
        "initiating_package_name": "com.android.vending",
        "installed_at": stamp(ins_at, 560),      # AFTER the click
        "language": "en",
        "last_error": "0",
        "needs_response_details": "1",
        "offline_mode_enabled": "0",
        "os_build": "S2SE32.28-28-4",
        "os_name": "android",
        "os_version": "12",
        "package_name": "com.creditsea.app",
        "retry_count": "0",
        "screen_density": "high",
        "screen_format": "long",
        "screen_size": "normal",
        "sent_at": stamp(t, 942),
        "session_count": "1",
        "store_name_from_system": "com.android.vending",
        "tracking_enabled": "1",
        "ui_mode": "1",
        "updated_at": stamp(ins_at, 560),        # == installed_at (genuine)
        "wait_time": "0.0",
        "wait_total": "0.0",
    }


def click_params(gaid, android_uuid, t_click, ins_at, reftag):
    t = time.time()
    return {
        "activity_kind": "click",
        "android_uuid": android_uuid,
        "api_level": "31",
        "app_token": APP_TOKEN,
        "app_version": "1.0.174",
        "attribution_deeplink": "1",
        "click_time": stamp(t_click, 0),
        "click_time_server": stamp(t_click - 1, 0),
        "client_sdk": CLIENT_SDK,
        "connectivity_type": "1",
        "country": "IN",
        "cpu_type": "arm64-v8a",
        "created_at": stamp(t, 961),
        "device_manufacturer": "motorola",
        "device_name": "moto g42",
        "device_type": "phone",
        "display_height": "2237",
        "display_width": "1080",
        "environment": "production",
        "foreground": "1",
        "google_play_instant": "0",
        "gps_adid": gaid,
        "gps_adid_attempt": "1",
        "gps_adid_src": "service",
        "hardware_name": "S2SE32.28-28-4",
        "install_begin_time": stamp(t_click + 5, 0),
        "install_begin_time_server": stamp(t_click + 4, 0),
        "install_version": "1.0.174",
        "installed_at": stamp(ins_at, 560),
        "language": "en",
        "needs_response_details": "1",
        "offline_mode_enabled": "0",
        "os_build": "S2SE32.28-28-4",
        "os_name": "android",
        "os_version": "12",
        "package_name": "com.creditsea.app",
        "referrer": "adjust_reftag=" + reftag,
        "referrer_api": "google",
        "screen_density": "high",
        "screen_format": "long",
        "screen_size": "normal",
        "sent_at": stamp(t, 975),
        "session_count": "1",
        "session_length": "0",
        "source": "install_referrer",
        "subsession_count": "1",
        "time_spent": "0",
        "tracking_enabled": "1",
        "ui_mode": "1",
        "updated_at": stamp(ins_at, 560),
    }


def attribution_params(gaid, android_uuid):
    t = time.time()
    return {
        "activity_kind": "attribution",
        "android_uuid": android_uuid,
        "api_level": "31",
        "app_token": APP_TOKEN,
        "app_version": "1.0.174",
        "attribution_deeplink": "1",
        "client_sdk": CLIENT_SDK,
        "created_at": stamp(t, 608),
        "device_name": "moto g42",
        "device_type": "phone",
        "environment": "production",
        "foreground": "1",
        "gps_adid": gaid,
        "gps_adid_attempt": "1",
        "gps_adid_src": "service",
        "initiated_by": "backend",               # the genuine value
        "needs_response_details": "1",
        "offline_mode_enabled": "0",
        "os_name": "android",
        "os_version": "12",
        "package_name": "com.creditsea.app",
        "sent_at": stamp(t, 656),
        "tracking_enabled": "1",
        "ui_mode": "1",
    }


# =========================================================================
# THE FUNNEL
# =========================================================================
def main():
    print("=" * 72, flush=True)
    print("[setup] signer VM sanity:", flush=True)
    ok = desc10_58.self_test()
    print("[setup] desc10_58.self_test -> %s" % ("OK" if ok else "FAIL"),
          flush=True)
    if not ok:
        print("[setup] ABORT: claims law failed self-test", flush=True)
        return 1

    # a completely fresh GAID, never used before -- for BOTH macros
    gaid = str(uuid.uuid4())
    android_uuid = str(uuid.uuid4())
    link = LINK_TEMPLATE.replace("{click_id}", gaid).replace("{sub3}", gaid)
    print("[setup] fresh GAID        : %s" % gaid, flush=True)
    print("[setup] fresh android_uuid: %s" % android_uuid, flush=True)
    print("[setup] click link        : %s" % link, flush=True)

    # ---- 1. the click ----------------------------------------------------
    t_click = time.time()
    hops, reftag = fire_click(link)
    print("[click] total %d hops, reftag=%s" % (len(hops), reftag), flush=True)
    if not reftag:
        print("[click] ABORT: no adjust_reftag in the redirect chain -- "
              "the sdk_click would have nothing to join", flush=True)
        return 1

    # ---- 2. wait ~14s (the Play install timing) --------------------------
    remain = (t_click + 14.0) - time.time()
    if remain > 0:
        print("[funnel] waiting %.1fs (Play install timing)" % remain,
              flush=True)
        time.sleep(remain)
    # the install story: click T -> install_begin T+5 -> installed_at T+12
    ins_at = int(t_click) + 12

    transport = OkHttpTransport(verbose=True)
    transport.headers["Client-SDK"] = CLIENT_SDK   # the Flutter composite
    try:
        # ---- 3. POST /session --------------------------------------------
        sp = session_params(gaid, android_uuid, t_click, ins_at)
        auth, second, info = sign(sp, "session")
        print("[sign] session  second=%d steps=%s" % (second,
              info.get("steps")), flush=True)
        st, body = transport.post("/session", sp, auth)
        print("[session] -> %d %s" % (st, body[:300]), flush=True)
        if st != 200:
            print("[session] ABORT: non-200", flush=True)
            return 1

        # ---- 4. wait ~3s, 5. POST /sdk_click ------------------------------
        time.sleep(3)
        cp = click_params(gaid, android_uuid, t_click, ins_at, reftag)
        auth, second, info = sign(cp, "click")
        print("[sign] click    second=%d steps=%s" % (second,
              info.get("steps")), flush=True)
        st, body = transport.post("/sdk_click", cp, auth)
        print("[sdk_click] -> %d %s" % (st, body[:300]), flush=True)
        if st != 200:
            print("[sdk_click] ABORT: non-200", flush=True)
            return 1

        # ---- 6. wait ~5s, 7. GET /attribution -----------------------------
        time.sleep(5)
        ap = attribution_params(gaid, android_uuid)
        auth, second, info = sign(ap, "attribution")
        print("[sign] attrib   second=%d steps=%s" % (second,
              info.get("steps")), flush=True)
        st, body = transport.get("/attribution", ap, auth)
        print("[attribution] -> %d %s" % (st, body[:600]), flush=True)
    finally:
        transport.close()

    # ---- verdict ----------------------------------------------------------
    print("=" * 72, flush=True)
    try:
        att = (json.loads(body).get("attribution") or {})
    except Exception:
        att = {}
    network = att.get("network")
    token = att.get("tracker_token")
    name = att.get("tracker_name")
    reattr = att.get("is_reattributed")
    nonorganic = bool(network) and network != "Organic" \
        and token != ORGANIC_TOKEN
    if nonorganic:
        print("*** VERDICT: NON-ORGANIC ***")
        print("    network=%s tracker=%s (%s) reattributed=%s"
              % (network, token, name, reattr))
        return 0
    print("*** VERDICT: ORGANIC / NOT JOINED ***")
    print("    network=%s tracker=%s (%s)" % (network, token, name))
    print("    full attribution body: %s" % body[:600])
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
