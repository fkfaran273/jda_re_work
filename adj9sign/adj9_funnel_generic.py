"""adj9_funnel_generic.py — DYNAMIC adj9 funnel for ANY adj9-signed app.

    import adj9_funnel_generic as funnel
    verdict = funnel.run(app_config, device_profile)

app_config: the same dict passed to adj9_signer_generic.configure()
device_profile: the device's fingerprint (any device-info dump as a dict)
click_link: the tracker's click URL (with {gaid} placeholder)

Deps: capstone, curl-cffi.  Takes ~1-2 min.
"""
import datetime
import json
import os
import re
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "adj9", "rev"))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "adj9", "rev", "creditsea"))

import adj9_signer_generic as signer
from signer_simple import auth_header


def _stamp(ts, ms, tz_label="+0530"):
    dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
          + datetime.timedelta(minutes=330))
    return dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms + "Z" + tz_label)


def _device_from_dump(dump):
    """Map any device-info dict -> a clean params dict for the Adjust SDK."""
    j = dump
    model = j.get("model") or j.get("name") or "phone"
    build = j.get("build") or j.get("display") or ""
    osv = str(j.get("os_version") or "")
    dm = j.get("display_metrics") or {}
    w, h = 1080, 2237
    res = j.get("resolution") or ""
    if "x" in res:
        a, b = res.lower().split("x", 1)
        if a.isdigit() and b.isdigit():
            w, h = sorted((int(a), int(b)))
    density = {"ldpi": "low", "mdpi": "medium", "hdpi": "high",
               "xhdpi": "high", "xxhdpi": "high", "xxxhdpi": "xhigh"}
    now = time.time()
    tz = j.get("timezone") or "+0530"
    sign = -1 if tz[0] == "-" else 1
    tz_min = sign * (int(tz[1:3]) * 60 + int(tz[3:5]))

    def stamp(ts, ms):
        dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
              + datetime.timedelta(minutes=tz_min))
        return dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms + "Z" + tz)

    gaid = j.get("gps_adid") or j.get("adid") or j.get("device_id") or ""
    params = {
        "app_token": j.get("_app_token", ""),
        "gps_adid": gaid,
        "android_uuid": j.get("android_uuid") or str(uuid.uuid4()),
        "api_level": str(j.get("sdk") or j.get("api_level") or ""),
        "app_version": j.get("app_version") or "1.0.0",
        "attribution_deeplink": "1",
        "connectivity_type": "1",
        "cpu_type": j.get("cpu_abi") or "arm64-v8a",
        "device_manufacturer": j.get("manufacturer") or "",
        "device_name": model,
        "device_type": j.get("device_type") or "phone",
        "display_height": str(h), "display_width": str(w),
        "enqueue_size": "0", "environment": "production",
        "first_error": "0", "foreground": "1",
        "gps_adid_attempt": "1", "gps_adid_src": "service",
        "hardware_name": build, "os_build": build,
        "initiating_package_name": "com.android.vending",
        "installed_at": j.get("installed_at") or stamp(now - 7 * 86400, 431),
        "language": (j.get("locale") or {}).get("language") or "en",
        "last_error": "0", "needs_response_details": "1",
        "offline_mode_enabled": "0",
        "os_name": "android", "os_version": osv,
        "package_name": j.get("package_name") or "",
        "screen_density": density.get(
            j.get("density_dpi") or (dm.get("density_dpi") or ""), "high"),
        "screen_format": j.get("screen_layout_format")
                         or dm.get("screen_layout_format") or "long",
        "screen_size": j.get("screen_layout_name")
                       or dm.get("screen_layout_name") or "normal",
        "sent_at": stamp(now, 768),
        "store_name_from_system": "com.android.vending",
        "tracking_enabled": "1", "ui_mode": "1",
        "updated_at": j.get("updated_at") or stamp(now - 2 * 86400, 448),
        "wait_time": "0.0", "wait_total": "0.0",
    }
    chrome_ua = j.get("User-Agent") or (
        "Mozilla/5.0 (Linux; Android %s; %s) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
        % (osv, model))
    dalvik_ua = ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
                 % (osv, model, build))
    return gaid, params, chrome_ua, dalvik_ua, stamp


def _click(click_link, gaid, chrome_ua):
    from curl_cffi import requests as cr
    url = click_link.replace("{gaid}", gaid)
    s = cr.Session(impersonate="chrome131")
    r = s.get(url, headers={"User-Agent": chrome_ua},
              allow_redirects=False, timeout=30)
    loc = r.headers.get("Location", "")
    m = re.search(r"adjust_reftag(?:%3D|=)([A-Za-z0-9]+)", loc)
    referrer = ("adjust_reftag=" + m.group(1)) if m else None
    print("[FUNNEL] click %d referrer=%s"
          % (r.status_code, (referrer or "NONE")[:60]), flush=True)
    return referrer


def _api(path, params, auth, client_sdk, ua, method="POST"):
    import http.client
    body = urllib.parse.urlencode(params).encode()
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    conn.putrequest(method, path + (("" if method == "POST" else "?"
                                     + urllib.parse.urlencode(params))),
                    skip_host=1, skip_accept_encoding=1)
    conn.putheader("Client-SDK", client_sdk)
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
    print("[FUNNEL] %-12s %d %s" % (kind_label(path), resp.status, out[:110]),
          flush=True)
    return resp.status, out


def kind_label(path):
    return {"/session": "session", "/sdk_click": "sdk_click",
            "/attribution": "attribution"}.get(path, path)


def run(app_config, device_dump, click_link):
    """The complete funnel: click → session → sdk_click → attribution.

    app_config: dict for adj9_signer_generic.configure()
    device_dump: dict from any device-info JSON
    click_link: the tracker's click URL (with {gaid} placeholder)
    Returns the attribution dict.
    """
    signer.configure(app_config)
    gaid, params, chrome_ua, dalvik_ua, stamp = _device_from_dump(device_dump)
    if not gaid:
        print("[FUNNEL] no GAID — expect Organic")
    else:
        print("[FUNNEL] gaid=%s" % gaid[:20], flush=True)
    client_sdk = app_config.get("client_sdk", "android5.8.0")
    app_token = app_config.get("app_token", "")
    package_name = params.get("package_name", "")

    t_click = time.time()
    referrer = _click(click_link, gaid, chrome_ua)
    if not referrer:
        return {"verdict": "no_referrer"}

    # ---- /session ----
    time.sleep(7)
    session = dict(params)
    session["activity_kind"] = "session"
    session["installed_at"] = stamp(t_click + 14, 560)
    session["updated_at"] = stamp(t_click + 14, 560)
    session["created_at"] = stamp(t_click + 20, 61)
    session["sent_at"] = stamp(t_click + 20, 68)
    auth = auth_header(signer.sign(session, "session")[0])
    code, body = _api("/session", session, auth, client_sdk, dalvik_ua)
    if code != 200:
        return {"verdict": "session_failed", "status": code, "body": body[:200]}

    # ---- /sdk_click ----
    time.sleep(3)
    cp = {k: v for k, v in session.items()
          if k not in ("first_error", "last_error", "retry_count")}
    cp.update({"source": "install_referrer", "referrer_api": "google",
               "referrer": referrer, "google_play_instant": "0",
               "install_version": session["app_version"],
               "created_at": stamp(t_click + 20, 24),
               "sent_at": stamp(t_click + 20, 31),
               "click_time": stamp(t_click, 0),
               "click_time_server": stamp(t_click - 2, 0),
               "install_begin_time": stamp(t_click + 8, 0),
               "install_begin_time_server": stamp(t_click + 6, 0),
               "activity_kind": "click"})
    auth = auth_header(signer.sign(cp, "click")[0])
    code, body = _api("/sdk_click", cp, auth, client_sdk, dalvik_ua)
    if code != 200:
        return {"verdict": "click_failed", "status": code, "body": body[:200]}

    # ---- /attribution ----
    time.sleep(5)
    ap = {"app_token": app_token, "gps_adid": gaid,
          "android_uuid": session["android_uuid"],
          "activity_kind": "attribution", "initiated_by": "sdk",
          "needs_response_details": "1", "environment": "production",
          "api_level": params["api_level"],
          "app_version": params["app_version"],
          "created_at": stamp(time.time(), 77),
          "device_name": params["device_name"],
          "device_type": params["device_type"],
          "gps_adid_src": params["gps_adid_src"],
          "os_name": "android", "os_version": params["os_version"],
          "package_name": params["package_name"], "tracking_enabled": "1",
          "country": params.get("country", "IN"),
          "client_sdk": client_sdk,
          "adj_verification": app_config.get("adj_verification", ""),
          "headers_id": app_config.get("headers_id", "10"),
          "adj_signing_id": app_config.get("adj_signing_id", "1500000"),
          "native_version": app_config.get("native_version", "5.0.0"),
          "algorithm": app_config.get("algorithm", "adj9")}
    auth = auth_header(signer.sign(ap, "attribution")[0])
    code, body = _api("/attribution", ap, auth, client_sdk, dalvik_ua,
                      method="GET")

    # ---- verdict ----
    print("=" * 60)
    try:
        att = json.loads(body).get("attribution") or {}
    except Exception:
        att = {}
    net = att.get("network")
    if net and net != "Organic":
        print("*** NON-ORGANIC: %s | %s | reattr=%s ***"
              % (net, att.get("tracker_name"), att.get("is_reattributed")))
        return {"verdict": "NON-ORGANIC", "network": net,
                "tracker": att.get("tracker_name"), "adid": None,
                "attribution": att}
    print("*** Organic / not joined: %s" % body[:150])
    return {"verdict": "Organic", "attribution": att}


import re  # for the reftag regex in _click
