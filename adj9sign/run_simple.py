"""run_simple.py — one-click non-organic booking, the simple linear version.

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

from signer_simple import sign_request, auth_header  # noqa: E402

APP_TOKEN = "jut9tib0eeps"
CLIENT_SDK = "android5.7.0"


def load_device(path):
    """Map a device dump -> (gaid, params, chrome_ua, dalvik_ua, stamp).

    Only device facts are extracted; the signature machinery is generic.
    installed_at/updated_at are synthesized 7d/2d ago (the re-attribution
    story) unless the dump carries real ones.
    """
    j = json.load(open(os.path.join(HERE, path), encoding="utf-8"))
    dm = j.get("display_metrics") or {}
    model = j.get("model") or j.get("name") or "phone"
    build = j.get("build") or j.get("display") or ""
    osv = str(j.get("os_version") or "")

    tz = j.get("timezone") or "+0000"
    sign = -1 if tz[0] == "-" else 1
    tz_min = sign * (int(tz[1:3]) * 60 + int(tz[3:5]))

    def stamp(ts, ms):
        dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
              + datetime.timedelta(minutes=tz_min))
        return dt.strftime("%%Y-%%m-%%dT%%H:%%M:%%S.%03dZ%s" % (ms, tz))

    w, h = 1080, 2237
    if "x" in (j.get("resolution") or ""):
        a, b = j["resolution"].lower().split("x", 1)
        if a.isdigit() and b.isdigit():
            w, h = sorted((int(a), int(b)))

    density = {"ldpi": "low", "mdpi": "medium", "hdpi": "high",
               "xhdpi": "high", "xxhdpi": "high", "xxxhdpi": "xhigh"}
    gaid = j.get("gps_adid") or j.get("adid") or j.get("device_id") or ""
    params = {                  # the session-params shape the tracker expects
        "app_token": APP_TOKEN,
        "gps_adid": gaid,
        "android_uuid": j.get("android_uuid") or str(uuid.uuid4()),
        "api_level": str(j.get("sdk") or ""),
        "app_version": j.get("app_version") or "3.14.0",
        "attribution_deeplink": "1",
        "connectivity_type": "1",
        "cpu_type": j.get("cpu_abi") or "arm64-v8a",
        "device_manufacturer": j.get("manufacturer") or "",
        "device_name": model,
        "device_type": j.get("device_type") or "phone",
        "display_height": str(h),
        "display_width": str(w),
        "environment": "production",
        "foreground": "1",
        "gps_adid_attempt": "1",
        "gps_adid_src": "service",
        "hardware_name": build,
        "os_build": build,
        "initiating_package_name": "com.android.vending",
        "installed_at": j.get("installed_at")
                        or stamp(time.time() - 7 * 86400, 431),
        "language": (j.get("locale") or {}).get("language") or "en",
        "needs_response_details": "1",
        "offline_mode_enabled": "0",
        "os_name": "android",
        "os_version": osv,
        "package_name": "com.penti.app",
        "screen_density": density.get(j.get("density_dpi")
                                      or (dm.get("density_dpi") or ""), "high"),
        "screen_format": j.get("screen_layout_format")
                         or dm.get("screen_layout_format") or "long",
        "screen_size": j.get("screen_layout_name")
                       or dm.get("screen_layout_name") or "normal",
        "store_name_from_system": "com.android.vending",
        "tracking_enabled": "1",
        "ui_mode": "1",
        "updated_at": j.get("updated_at")
                      or stamp(time.time() - 2 * 86400, 448),
    }
    chrome_ua = (j.get("User-Agent")
                 or "Mozilla/5.0 (Linux; Android %s; %s) Mobile Safari/537.36"
                 % (osv, model))
    dalvik_ua = ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
                 % (osv, model, build))
    return gaid, params, chrome_ua, dalvik_ua, stamp


def click(gaid, chrome_ua):
    """Fire the tracker click from a browser fingerprint."""
    from curl_cffi import requests as cr
    url = LINK + "&click_id=" + gaid + "&idfa=" + gaid + "&gps_adid=" + gaid
    r = cr.Session(impersonate="chrome131").get(
        url, headers={"User-Agent": chrome_ua},
        allow_redirects=False, timeout=30)
    loc = r.headers.get("Location", "")
    referrer = (urllib.parse.unquote(loc.split("referrer=", 1)[1])
                if "referrer=" in loc else None)
    print("[RUN] click %d referrer=%s"
          % (r.status_code, (referrer or "NONE")[:60]), flush=True)
    return referrer


def send(path, params, kind, ua, method="POST"):
    """Sign THIS request (own claims/second/seed) and call the endpoint."""
    import http.client
    auth = auth_header(sign_request(params, kind)[0])
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
    time.sleep(7)
    session = dict(params)
    session.update({"session_count": "1", "session_length": "0",
                    "time_spent": "0", "subsession_count": "1",
                    "created_at": stamp(t_click + 7, 61),
                    "sent_at": stamp(t_click + 7, 68)})
    code, _ = send("/session", session, "session", dalvik_ua)
    if code != 200:
        return 1

    # ---- /sdk_click: the click joins the device -----------------------
    time.sleep(3)
    cp = {k: v for k, v in session.items()
          if k not in ("first_error", "last_error", "retry_count")}
    cp.update({"source": "install_referrer", "referrer_api": "google",
               "referrer": referrer, "google_play_instant": "0",
               "install_version": session["app_version"],
               "created_at": stamp(t_click + 8, 24),
               "sent_at": stamp(t_click + 8, 31),
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
