"""adj9_funnel.py — the DYNAMIC adj9 attribution funnel (app-independent).

Reads campaign_data.json + device_data.json from this directory and runs the
complete flow.  Swapping apps = swapping the two JSON files.  Nothing here is
app-specific:

    fresh GAID + android_uuid (uuid4, NEVER reused across runs)
      -> click   campaign_data.click_link with {gaid} replaced
                 (curl_cffi chrome131; reftag from the redirect Location)
      -> wait    t_click + 14s  (the Play install timing)
      -> POST /session      installed_at/updated_at AFTER the click (critical)
      -> wait ~3s
      -> POST /sdk_click    the click joins the device (adjust_reftag)
      -> wait ~3s
      -> GET  /attribution  -> the verdict

Every request is signed fresh by adj9_signer (own claims, own second, own
seed; ~15-25s per VM signing, 3 signings per run).  The Client-SDK header on
every call is campaign_data.client_sdk (the Flutter composite).  The wire
param shapes are the proven ones from run_creditsea.py.

Timestamps use device_data.timezone (e.g. +0530): the base device story is
installed_at ~7d ago / updated_at ~2d ago, then the session and sdk_click
override installed_at/updated_at to t_click + 14s — AFTER the click, which
the server checks for attribution.

Deps: capstone, curl-cffi.  Takes ~1-2 min.

    python adj9_funnel.py
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

# SELF-CONTAINED: the sibling adj9_signer.py carries the whole signing stack
# (VM + claims law) in one file.  THIS directory is the only path added — no
# adj9sign\ parent and no adj9\rev\ paths on sys.path at all.
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import adj9_signer  # noqa: E402  (the local, fully self-contained signer)


# =========================================================================
# config + time helpers
# =========================================================================
def load_json(name):
    path = os.path.join(HERE, name)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def tz_parts(tz_label):
    """'+0530' -> ('+0530', 330).  'Z'/'UTC' -> ('Z', 0)."""
    tz_label = tz_label or "Z"
    if tz_label in ("Z", "UTC", "+0000", "-0000"):
        return "Z", 0
    sign = -1 if tz_label[0] == "-" else 1
    minutes = int(tz_label[1:3]) * 60 + int(tz_label[3:5])
    return tz_label, sign * minutes


def make_stamp(tz_label):
    """The genuine Adjust timestamp literal in the device's timezone:
    '<IST wall time>.<ms>Z+0530' (the 'Z' rides even for non-UTC zones —
    exactly as the genuine device emits it)."""
    _, tz_min = tz_parts(tz_label)

    def stamp(ts, ms):
        dt = (datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc)
              + datetime.timedelta(minutes=tz_min))
        return (dt.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % ms
                + "Z" + tz_label)
    return stamp


def uas(dev):
    """The browser UA (the click) and the Dalvik UA (the API calls)."""
    model, osv, build = dev["device_name"], dev["os_version"], dev["os_build"]
    chrome_ua = ("Mozilla/5.0 (Linux; Android %s; %s) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/131.0.6778.200 Mobile "
                 "Safari/537.36" % (osv, model))
    dalvik_ua = ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
                 % (osv, model, build))
    return chrome_ua, dalvik_ua


# =========================================================================
# 1. THE CLICK
# =========================================================================
def fire_click(link, chrome_ua):
    """Browser click (chrome131), following the redirect chain by hand until
    the adjust_reftag shows up (it rides the Play referrer)."""
    from curl_cffi import requests as cr
    s = cr.Session(impersonate="chrome131")
    url = link
    reftag = None
    for i in range(10):
        r = s.get(url, headers={"User-Agent": chrome_ua},
                  allow_redirects=False, timeout=30)
        loc = r.headers.get("Location", "")
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
            print("[click] no more redirects; reftag not found", flush=True)
            break
        url = urllib.parse.urljoin(url, loc)
    return reftag


# =========================================================================
# THE WIRE SHAPES — run_creditsea.py's proven lists, values from the JSONs
# =========================================================================
def base_params(campaign, dev, gaid, android_uuid, stamp):
    """The shared device+identity map (the pre-click install story: the app
    installed ~7d ago, last updated ~2d ago)."""
    now = time.time()
    return {
        "app_token": campaign["app_token"],
        "gps_adid": gaid,
        "android_uuid": android_uuid,
        "api_level": dev["api_level"],
        "app_version": dev["app_version"],
        "attribution_deeplink": "1",
        "client_sdk": campaign["client_sdk"],
        "connectivity_type": "1",
        "country": dev["country"],
        "cpu_type": dev["cpu_type"],
        "created_at": stamp(now, 761),          # overwritten per request
        "device_manufacturer": dev["device_manufacturer"],
        "device_name": dev["device_name"],
        "device_type": dev["device_type"],
        "display_height": dev["display_height"],
        "display_width": dev["display_width"],
        "enqueue_size": "0",
        "environment": "production",
        "first_error": "0",
        "foreground": "1",
        "gps_adid_attempt": "1",
        "gps_adid_src": "service",
        "hardware_name": dev["hardware_name"],
        "initiating_package_name": "com.android.vending",
        "installed_at": stamp(now - 7 * 86400, 560),   # ~7d ago (pre-click)
        "language": dev["language"],
        "last_error": "0",
        "needs_response_details": "1",
        "offline_mode_enabled": "0",
        "os_build": dev["os_build"],
        "os_name": "android",
        "os_version": dev["os_version"],
        "package_name": dev.get("package_name") or campaign["package_name"],
        "retry_count": "0",
        "screen_density": dev["screen_density"],
        "screen_format": dev["screen_format"],
        "screen_size": dev["screen_size"],
        "sent_at": stamp(now, 768),             # overwritten per request
        "session_count": "1",
        "session_length": "0",
        "store_name_from_system": "com.android.vending",
        "subsession_count": "1",
        "time_spent": "0",
        "tracking_enabled": "1",
        "ui_mode": "1",
        "updated_at": stamp(now - 2 * 86400, 560),     # ~2d ago (pre-click)
        "wait_time": "0.0",
        "wait_total": "0.0",
    }


def session_params(base, stamp, t_click, ins_at):
    """/session — the identity arrives.  installed_at/updated_at AFTER the
    click (the server checks this); created_at/sent_at = the session time."""
    p = dict(base)
    p["installed_at"] = stamp(t_click + 14, 560)   # AFTER the click
    p["updated_at"] = stamp(t_click + 14, 560)     # AFTER the click
    p.update({"session_count": "1", "session_length": "0",
              "time_spent": "0", "subsession_count": "1",
              "created_at": stamp(t_click + 20, 61),
              "sent_at": stamp(t_click + 20, 68),
              "activity_kind": "session"})
    return p


def click_params(base, session, stamp, t_click, ins_at, reftag):
    """/sdk_click — the click joins the device (run_creditsea.py shape)."""
    p = {k: v for k, v in session.items()
         if k not in ("first_error", "last_error", "retry_count")}
    p["installed_at"] = stamp(t_click + 14, 560)   # AFTER the click
    p["updated_at"] = stamp(t_click + 14, 560)     # AFTER the click
    p.update({"source": "install_referrer", "referrer_api": "google",
              "referrer": "adjust_reftag=" + reftag,
              "google_play_instant": "0",
              "install_version": session["app_version"],
              "created_at": stamp(t_click + 20, 24),
              "sent_at": stamp(t_click + 20, 31),
              "click_time": stamp(t_click, 0),
              "click_time_server": stamp(t_click - 2, 0),
              "install_begin_time": stamp(t_click + 6, 0),
              "install_begin_time_server": stamp(t_click + 4, 0),
              "activity_kind": "click"})
    return p


def attribution_params(base, campaign, session, stamp, gaid):
    """/attribution — the verdict (run_creditsea.py shape)."""
    return {
        "app_token": campaign["app_token"],
        "gps_adid": gaid,
        "android_uuid": session["android_uuid"],
        "activity_kind": "attribution",
        "initiated_by": "sdk",
        "needs_response_details": "1",
        "environment": "production",
        "api_level": base["api_level"],
        "app_version": base["app_version"],
        "created_at": stamp(time.time(), 77),
        "device_name": base["device_name"],
        "device_type": base["device_type"],
        "gps_adid_src": base["gps_adid_src"],
        "os_name": "android",
        "os_version": base["os_version"],
        "package_name": base["package_name"],
        "tracking_enabled": "1",
    }


# =========================================================================
# THE SIGNED TRANSPORT (run_creditsea.py's proven http.client path)
# =========================================================================
def send(path, params, kind, ua, method="POST"):
    """Sign THIS request fresh and call the endpoint.  The Client-SDK header
    (the Flutter composite) is mandatory on EVERY call."""
    import http.client
    blob, _second, _info = adj9_signer.sign(params, kind)
    auth = adj9_signer.auth_header(blob)
    body = urllib.parse.urlencode(params).encode()
    conn = http.client.HTTPSConnection(adj9_signer.api_host(), 443, timeout=30)
    conn.putrequest(method, path + (("" if method == "POST" else "?"
                                     + urllib.parse.urlencode(params))),
                    skip_host=1, skip_accept_encoding=1)
    conn.putheader("Client-SDK", adj9_signer.client_sdk())
    conn.putheader("Authorization", auth)
    conn.putheader("User-Agent", ua)
    conn.putheader("Host", adj9_signer.api_host())
    if method == "POST":
        conn.putheader("Content-Type", "application/x-www-form-urlencoded")
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body if method == "POST" else None)
    resp = conn.getresponse()
    out = resp.read().decode("utf-8", "replace")
    conn.close()
    print("[funnel] %-12s %d %s" % (kind, resp.status, out[:110]), flush=True)
    return resp.status, out


# =========================================================================
# THE FUNNEL
# =========================================================================
def main():
    campaign = load_json("campaign_data.json")
    dev = load_json("device_data.json")
    tz_label = dev.get("timezone", "+0530")
    stamp = make_stamp(tz_label)
    chrome_ua, dalvik_ua = uas(dev)

    # 1-2. the signer + a completely fresh identity (never reused)
    adj9_signer.configure(campaign)
    print(adj9_signer.status(), flush=True)
    gaid = str(uuid.uuid4())
    android_uuid = str(uuid.uuid4())
    print("[funnel] fresh GAID        : %s" % gaid, flush=True)
    print("[funnel] fresh android_uuid: %s" % android_uuid, flush=True)

    # 3. the click ({gaid} -> the fresh GAID, everywhere incl. the callbacks)
    link = campaign["click_link"].replace("{gaid}", gaid)
    print("[funnel] click link: %s" % link[:140], flush=True)
    t_click = time.time()
    reftag = fire_click(link, chrome_ua)
    if not reftag:
        print("[funnel] ABORT: no adjust_reftag in the redirect chain — "
              "the sdk_click would have nothing to join", flush=True)
        return 1

    # 4. the Play install timing: click T -> installed_at T+14 (AFTER click)
    remain = (t_click + 14.0) - time.time()
    if remain > 0:
        print("[funnel] waiting %.1fs (Play install timing; installed_at "
              "lands AFTER the click)" % remain, flush=True)
        time.sleep(remain)
    ins_at = int(t_click) + 14

    base = base_params(campaign, dev, gaid, android_uuid, stamp)

    # 5-6. POST /session (5.8.0 signature)
    session = session_params(base, stamp, t_click, ins_at)
    code, _ = send("/session", session, "session", dalvik_ua)
    if code != 200:
        print("[funnel] ABORT: /session non-200", flush=True)
        return 1

    # 7-8. POST /sdk_click (5.8.0 signature)
    time.sleep(3)
    cp = click_params(base, session, stamp, t_click, ins_at, reftag)
    code, _ = send("/sdk_click", cp, "click", dalvik_ua)
    if code != 200:
        print("[funnel] ABORT: /sdk_click non-200", flush=True)
        return 1

    # 9-10. GET /attribution (5.8.0 signature) -> the verdict
    time.sleep(3)
    ap = attribution_params(base, campaign, session, stamp, gaid)
    code, body = send("/attribution", ap, "attribution", dalvik_ua,
                      method="GET")

    # ---- the verdict (reported honestly, whatever it is) ------------------
    print("=" * 60, flush=True)
    print("[funnel] full attribution response:", flush=True)
    print(body, flush=True)
    try:
        att = json.loads(body).get("attribution") or {}
    except Exception:
        att = {}
    network = att.get("network")
    if network and network != "Organic":
        print("*** VERDICT: NON-ORGANIC: %s | %s | reattr=%s ***"
              % (network, att.get("tracker_name"),
                 att.get("is_reattributed")), flush=True)
        return 0
    print("*** VERDICT: ORGANIC / NOT JOINED (network=%s tracker=%s) ***"
          % (network, att.get("tracker_name")), flush=True)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
