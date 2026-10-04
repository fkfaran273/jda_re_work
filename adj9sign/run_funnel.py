"""run_funnel.py — ONE-CLICK fully-offline adj9 non-organic booking.

    python run_funnel.py            # uses GAID below (or random if empty)
    python run_funnel.py <gaid> [android_uuid]

Flow: click (python, chrome131 fingerprint) -> /session -> /sdk_click ->
/attribution, EVERY request signed fresh by adj9_signer (its own claims, own
second, own seed S). No device, no frida, no app — pure Python.

Deps:  pip install capstone curl-cffi
Takes ~1-3 min (3 VM runs of the signer).
"""
import json
import os
import struct
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# =========================================================================
# CONFIG — edit these
# =========================================================================
# The click link (tracker). {adgroup} is replaced by ADGROUP below.
LINK = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic")

# Device profiles. Each holds: gaid (REAL device GAID), auid (android_uuid,
# fresh per install), ua (Dalvik UA for the API calls), chrome_ua (the click
# browser UA), device_data (the session param set cloned from the device).
# installed_at / updated_at are the package-manager firstInstallTime /
# lastUpdateTime: they PREdate the click, giving the re-attribution story.
DEVICE_PROFILES = {
    "moto_g42": {
        "gaid": "7cc81be0-60a0-4342-a878-eb5ee4f2634a",
        "auid": "1b06322b-9070-4bdc-a231-2199bef3f3f5",
        "ua": "Dalvik/2.1.0 (Linux; U; Android 12; moto g 42 Build/S2SE32.28-28-4)",
        "chrome_ua": ("Mozilla/5.0 (Linux; Android 12; moto g 42) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/131.0.6778.200 Mobile Safari/537.36"),
        "device_data": {
            "android_uuid": "",                  # filled from auid
            "api_level": "31",
            "app_token": "jut9tib0eeps",
            "app_version": "3.14.0",
            "attribution_deeplink": "1",
            "connectivity_type": "1",
            "cpu_type": "arm64-v8a",
            "device_manufacturer": "motorola",
            "device_name": "moto g42",
            "device_type": "phone",
            "display_height": "2237",
            "display_width": "1080",
            "enqueue_size": "0",
            "environment": "production",
            "first_error": "0",
            "foreground": "1",
            "gps_adid": "",                      # filled from gaid
            "gps_adid_attempt": "1",
            "gps_adid_src": "service",
            "hardware_name": "S2SE32.28-28-4",
            "initiating_package_name": "com.android.vending",
            "installed_at": "2026-09-14T17:52:12.431Z+0530",
            "language": "tr",
            "last_error": "0",
            "needs_response_details": "1",
            "offline_mode_enabled": "0",
            "os_build": "S2SE32.28-28-4",
            "os_name": "android",
            "os_version": "12",
            "package_name": "com.penti.app",
            "retry_count": "0",
            "screen_density": "high",
            "screen_format": "long",
            "screen_size": "normal",
            "sent_at": "",
            "store_name_from_system": "com.android.vending",
            "tracking_enabled": "1",
            "ui_mode": "1",
            "updated_at": "2026-09-24T20:36:30.448Z+0530",
            "wait_time": "0.0",
            "wait_total": "0.0",
        },
    },
    "moto_g64": {
        "gaid": "9b9f265c-f930-4ee5-9094-29bdh759620e",
        "auid": "2470e87e-af76-45ad-96e6-4e211fc8f27d",
        "ua": "Dalvik/2.1.0 (Linux; U; Android 15; moto g64 5G Build/V1TD35H.83-20-5)",
        "chrome_ua": ("Mozilla/5.0 (Linux; Android 15; moto g64 5G) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/154.0.8037.49 Mobile Safari/537.36"),
        "device_data": {
            "android_uuid": "",                  # filled from auid
            "api_level": "35",
            "app_token": "jut9tib0eeps",
            "app_version": "3.14.0",
            "attribution_deeplink": "1",
            "connectivity_type": "1",
            "cpu_type": "arm64-v8a",
            "device_manufacturer": "motorola",
            "device_name": "moto g64 5G",
            "device_type": "phone",
            "display_height": "2400",
            "display_width": "1080",
            "enqueue_size": "0",
            "environment": "production",
            "first_error": "0",
            "foreground": "1",
            "gps_adid": "",                      # filled from gaid
            "gps_adid_attempt": "1",
            "gps_adid_src": "service",
            "hardware_name": "V1TD35H.83-20-5",
            "initiating_package_name": "com.android.vending",
            "installed_at": "2026-09-22T10:15:00.000Z+0530",
            "language": "en",
            "last_error": "0",
            "needs_response_details": "1",
            "offline_mode_enabled": "0",
            "os_build": "V1TD35H.83-20-5",
            "os_name": "android",
            "os_version": "15",
            "package_name": "com.penti.app",
            "retry_count": "0",
            "screen_density": "high",
            "screen_format": "long",
            "screen_size": "large",
            "sent_at": "",
            "store_name_from_system": "com.android.vending",
            "tracking_enabled": "1",
            "ui_mode": "1",
            "updated_at": "2026-09-27T18:40:12.448Z+0530",
            "wait_time": "0.0",
            "wait_total": "0.0",
        },
    },
}
PROFILE = "moto_g64"   # <- active device ("moto_g42" or "moto_g64")

APP_TOKEN = "jut9tib0eeps"
CLIENT_SDK = "android5.7.0"
WIN_HEAD = (0x2B, 0x48)   # solved genuine d0 phase for request signings

import adj9_signer as S  # noqa: E402  (after sys.path setup)

D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd") # app cert

TZ_MIN, TZ_LABEL = 330, "+0530"   # active device timezone (set per profile)


def log(msg):
    print("[FUN] %s" % msg, flush=True)


# ---------------------------------------------------------------------------
# DYNAMIC device mapping: feed ANY device-info JSON dump -> profile
# ---------------------------------------------------------------------------
_DENSITY = {"ldpi": "low", "mdpi": "medium", "hdpi": "high", "tvdpi": "high",
            "xhdpi": "high", "xxhdpi": "high", "xxxhdpi": "xhigh"}


def _tz_minutes(label):
    """'+0530' / '-0800' -> minutes east of UTC."""
    try:
        s = label.replace("Z", "+0000")
        sign = -1 if s[0] == "-" else 1
        return sign * (int(s[1:3]) * 60 + int(s[3:5]))
    except Exception:
        return 330


def _fmt_tz(ts, ms, tz_min, tz_label):
    import datetime
    dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
          + datetime.timedelta(minutes=tz_min))
    return dt.strftime("%%Y-%%m-%%dT%%H:%%M:%%S.%03dZ%s" % (ms, tz_label))


def device_from_dump(raw):
    """Map a raw device-info JSON dump (any farm-tool format) into a profile
    dict {gaid, auid, ua, chrome_ua, device_data}. The signature machinery is
    fully dynamic; this only translates device facts into the session-params
    shape the tracker expects. Optional JSON keys override the synthesized
    ones: gps_adid, android_uuid, installed_at, updated_at, app_version."""
    j = raw if isinstance(raw, dict) else json.loads(raw)
    dm = j.get("display_metrics") or {}
    loc = j.get("locale") or {}
    model = j.get("model") or j.get("name") or "phone"
    build = j.get("build") or j.get("display") or ""
    osv = str(j.get("os_version") or "")
    tz_label = j.get("timezone") or "+0000"
    tz_min = _tz_minutes(tz_label)

    # display: prefer the resolution string, keep portrait w<h
    w, h = 1080, 2237
    res = j.get("resolution") or ""
    if "x" in res:
        a, b = res.lower().split("x", 1)
        if a.isdigit() and b.isdigit():
            w, h = (int(a), int(b)) if int(a) < int(b) else (int(b), int(a))

    gaid = (j.get("gps_adid") or j.get("adid") or j.get("device_id") or "")
    now = time.time()
    installed = j.get("installed_at") or _fmt_tz(now - 7 * 86400, 431,
                                                 tz_min, tz_label)
    updated = j.get("updated_at") or _fmt_tz(now - 2 * 86400, 448,
                                             tz_min, tz_label)
    dd = {
        "android_uuid": j.get("android_uuid") or "",
        "api_level": str(j.get("sdk") or j.get("kernel") or ""),
        "app_token": APP_TOKEN,
        "app_version": j.get("app_version") or "3.14.0",
        "attribution_deeplink": "1",
        "connectivity_type": "1",
        "cpu_type": j.get("cpu_abi") or "arm64-v8a",
        "device_manufacturer": j.get("manufacturer") or "",
        "device_name": model,
        "device_type": j.get("device_type") or "phone",
        "display_height": str(h),
        "display_width": str(w),
        "enqueue_size": "0",
        "environment": "production",
        "first_error": "0",
        "foreground": "1",
        "gps_adid": gaid,
        "gps_adid_attempt": "1",
        "gps_adid_src": "service",
        "hardware_name": build,
        "initiating_package_name": "com.android.vending",
        "installed_at": installed,
        "language": loc.get("language") or "en",
        "last_error": "0",
        "needs_response_details": "1",
        "offline_mode_enabled": "0",
        "os_build": build,
        "os_name": "android",
        "os_version": osv,
        "package_name": "com.penti.app",
        "retry_count": "0",
        "screen_density": _DENSITY.get(j.get("density_dpi")
                                       or (dm.get("density_dpi") or ""),
                                       "high"),
        "screen_format": (j.get("screen_layout_format")
                          or dm.get("screen_layout_format") or "long"),
        "screen_size": (j.get("screen_layout_name")
                        or dm.get("screen_layout_name") or "normal"),
        "sent_at": "",
        "store_name_from_system": "com.android.vending",
        "tracking_enabled": "1",
        "ui_mode": "1",
        "updated_at": updated,
        "wait_time": "0.0",
        "wait_total": "0.0",
    }
    chrome_ua = (j.get("User-Agent") or j.get("user_agent")
                 or "Mozilla/5.0 (Linux; Android %s; %s) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
                 % (osv, model))
    return {
        "gaid": gaid,
        "auid": j.get("android_uuid") or str(uuid.uuid4()),
        "ua": "Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
              % (osv, model, build),
        "chrome_ua": chrome_ua,
        "device_data": dd,
        "tz_min": tz_min,
        "tz_label": tz_label,
    }


def load_profile(arg):
    """argv[1] may be a device-JSON dump (path to a file or inline JSON)."""
    raw = None
    if arg:
        if arg.lstrip().startswith("{"):
            raw = arg
        elif os.path.exists(arg) and arg.lower().endswith(".json"):
            raw = open(arg, encoding="utf-8").read()
    if raw is None:
        return None
    cfg = device_from_dump(raw)
    log("dynamic device JSON: %s %s (gaid=%s)"
        % (cfg["device_data"]["device_name"],
           cfg["device_data"]["os_version"], cfg["gaid"]))
    return cfg


def stamp(ts, ms=31):
    """Wire timestamp in the ACTIVE device's timezone."""
    return _fmt_tz(ts, ms, TZ_MIN, TZ_LABEL)


def sign(params, kind):
    """One fresh signing: own second, own seed S, own claims."""
    val = dict(params)
    val.update({"activity_kind": kind, "client_sdk": CLIENT_SDK,
                "adj_signing_id": "1500000", "headers_id": "10",
                "native_version": "5.0.0",
                "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"})
    sec = int(time.time())
    Sv = struct.unpack(">I", os.urandom(4))[0]
    d0w, d2w, d4w = S.region(Sv, 0, 0, head=WIN_HEAD)
    padded, unpadded = S.claims_for_law(val, kind)
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8),
          4: (8, 0, d4), 2: (1, 0, struct.pack(">I", d2w)),
          7: (1, 0, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, struct.pack(">I", 0)), 6: (1, 0, struct.pack(">I", 0)),
          1: (0, 0, b""), 3: (0, 0, b"")}
    descs = [by[i] for i in S.VA_ORDER]
    blob, info = S.finex_mint(descs, sec)
    log("signed %-11s sec=%d S=%08x st=%s %dB"
        % (kind, sec, Sv, info["status"], len(blob)))
    return S.auth_header(blob)


def api(path, params, auth, method="POST"):
    import http.client
    body = urllib.parse.urlencode(params).encode()
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    conn.putrequest(method, path + (("?" + urllib.parse.urlencode(params))
                                    if method == "GET" else ""),
                    skip_host=1, skip_accept_encoding=1)
    headers = [("Client-SDK", CLIENT_SDK), ("Authorization", auth),
               ("User-Agent", UA), ("Host", "app.adjust.com")]
    if method == "POST":
        headers += [("Content-Type", "application/x-www-form-urlencoded"),
                    ("Connection", "Keep-Alive"), ("Accept-Encoding", "gzip"),
                    ("Content-Length", str(len(body)))]
    for k, v in headers:
        conn.putheader(k, v)
    conn.endheaders(body if method == "POST" else None)
    resp = conn.getresponse()
    data = resp.read().decode("utf-8", "replace")
    conn.close()
    return resp.status, data


def click(gaid, chrome_ua):
    """Fire the tracker click with a chrome131 TLS fingerprint."""
    from curl_cffi import requests as cr
    url = LINK
    url += ("&click_id=" + gaid + "&idfa=" + gaid + "&gps_adid=" + gaid)
    s = cr.Session(impersonate="chrome131")
    r = s.get(url, headers={"User-Agent": chrome_ua},
              allow_redirects=False, timeout=30)
    loc = r.headers.get("Location", "")
    referrer = (urllib.parse.unquote(loc.split("referrer=", 1)[1])
                if "referrer=" in loc else None)
    log("click %d referrer=%s" % (r.status_code, (referrer or "NONE")[:60]))
    return r.status_code, referrer


def main():
    global PROFILE, UA, TZ_MIN, TZ_LABEL
    t0 = time.time()
    dyn = load_profile(sys.argv[1]) if len(sys.argv) > 1 else None
    if dyn:
        cfg, PROFILE = dyn, "dynamic(json)"
    else:
        if len(sys.argv) > 3:
            PROFILE = sys.argv[3]
        cfg = DEVICE_PROFILES[PROFILE]
    UA = cfg["ua"]
    TZ_MIN = cfg.get("tz_min", 330)
    TZ_LABEL = cfg.get("tz_label", "+0530")
    gaid, auid = cfg["gaid"], cfg["auid"]
    if not dyn and len(sys.argv) > 1:
        gaid = sys.argv[1]
    if not dyn and len(sys.argv) > 2:
        auid = sys.argv[2]
    if not gaid:
        gaid, auid = str(uuid.uuid4()), str(uuid.uuid4())
        log("NO GAID IN DEVICE DATA — random-uuid CONTROL mode (expect Organic)")
    dev = dict(cfg["device_data"])
    dev["gps_adid"] = gaid
    dev["android_uuid"] = auid or str(uuid.uuid4())
    log("device=%s gaid=%s" % (PROFILE, gaid))
    RES = {"gaid": gaid, "android_uuid": dev["android_uuid"],
           "profile": PROFILE}

    # 1. click ------------------------------------------------------------
    code, referrer = click(gaid, cfg["chrome_ua"])
    RES["click"] = {"http": code, "referrer": referrer}
    if not referrer:
        log("NO REFERRER — abort")
        return 1
    t_click = time.time()

    # 2. /session ----------------------------------------------------------
    dev.update({"session_count": "1", "session_length": "0", "time_spent": "0",
                "subsession_count": "1",
                "created_at": stamp(t_click + 7, 61),
                "sent_at": stamp(t_click + 7, 68)})
    auth = sign(dev, "session")
    time.sleep(2)
    code, body = api("/session", dev, auth)
    log("SESSION %d %s" % (code, body[:120]))
    RES["session"] = {"http": code, "body": body[:300]}
    if code != 200:
        return finish(RES, t0, "session-failed")

    # 3. /sdk_click --------------------------------------------------------
    cp = {k: v for k, v in dev.items() if k not in ("wait_time", "wait_total",
                                                    "first_error", "last_error",
                                                    "retry_count",
                                                    "enqueue_size")}
    cp.update({"source": "install_referrer", "referrer_api": "google",
               "referrer": referrer, "google_play_instant": "0",
               "install_version": dev["app_version"],
               "created_at": stamp(t_click + 8, 24),
               "sent_at": stamp(t_click + 8, 31),
               "click_time": stamp(t_click, 0),
               "click_time_server": stamp(t_click - 2, 0),
               "install_begin_time": stamp(t_click + 6, 0),
               "install_begin_time_server": stamp(t_click + 4, 0),
               "activity_kind": "click"})
    auth = sign(cp, "click")
    time.sleep(2)
    code, body = api("/sdk_click", cp, auth)
    log("SDK_CLICK %d %s" % (code, body[:120]))
    RES["sdk_click"] = {"http": code, "body": body[:300]}
    if code != 200:
        return finish(RES, t0, "click-failed")

    # 4. /attribution -------------------------------------------------------
    ap = {"app_token": APP_TOKEN, "gps_adid": gaid,
          "android_uuid": dev["android_uuid"],
          "activity_kind": "attribution", "initiated_by": "sdk",
          "needs_response_details": "1", "environment": "production",
          "api_level": dev["api_level"], "app_version": dev["app_version"],
          "created_at": stamp(time.time(), 77),
          "device_name": dev["device_name"], "device_type": dev["device_type"],
          "gps_adid_src": dev["gps_adid_src"], "os_name": "android",
          "os_version": dev["os_version"], "package_name": dev["package_name"],
          "tracking_enabled": "1"}
    auth = sign(ap, "attribution")
    time.sleep(2)
    code, body = api("/attribution", ap, auth, method="GET")
    log("ATTRIBUTION %d %s" % (code, body[:200]))
    RES["attribution"] = {"http": code, "body": body[:600]}

    # verdict ----------------------------------------------------------------
    print("=" * 62)
    verdict = "unknown"
    try:
        att = json.loads(body).get("attribution") or {}
        net = att.get("network")
        if net and net != "Organic":
            verdict = "NON-ORGANIC"
            print("*** NON-ORGANIC — GOAL ***")
            print("*** %s | %s | reattr=%s ***"
                  % (net, att.get("tracker_name"),
                     att.get("is_reattributed")))
        else:
            verdict = "Organic"
            print("*** Organic — identity did not join the click ***")
    except Exception:
        print("*** attribution body not json: %s" % body[:120])
    RES["verdict"] = verdict
    return finish(RES, t0, verdict)


def finish(RES, t0, verdict):
    RES["elapsed_s"] = round(time.time() - t0, 1)
    out = os.path.join(HERE, "funnel_result.json")
    json.dump(RES, open(out, "w"), indent=1)
    print("=" * 62)
    print("verdict: %s  (%.0f s)  saved %s"
          % (verdict, RES["elapsed_s"], out))
    return 0 if verdict == "NON-ORGANIC" else 1


if __name__ == "__main__":
    sys.exit(main())
