"""manual_test.py - manual tester: paste referrer + GAID + device JSON, run 3 calls.

Reads manual_input.json in the same folder. Prints a step-by-step verdict log.
"""
import datetime as dt
import http.client
import json
import os
import re
import struct
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
from region_synth import synth_region, check

IN = {
  "link": "https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic&click_id={click_id}&idfa={sub3}&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fpostback%3Fclick_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp&event_callback_bfi71x=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fevents%3Fclick_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp",
  "fire_click": True,
  "creative": "mytest",
  "device": {"kernel": "16", "locale": {"country": "IN", "language": "en"}, "ram": {"available": "7558", "shown": "8192"}, "os_incremental": "13578956", "bluetooth": "3.0", "hardware": "", "imei": "863413676183248", "cpu_core": "8", "private_ip": "10.0.135.93", "device_type": "phone", "timezone": "+0530", "serial": "d61e9edd951d4507", "mnc": "52", "android_id": "a80668a8541eacd7", "cpu_arch": "aarch64", "display_metrics": {"ypx": "1080", "screen_layout_name": "large", "screen_layout_format": "long", "xpx": "2400", "ydp": 417.795, "xdp": 417.827, "aspect_ratio": "15:6", "density_dpi": "xxhdpi", "screen_layout_size": 3}, "last_rebooted_at": 1789871229279, "network_band": "LTE", "cpu_abi2": "", "User-Agent": "Mozilla/5.0 (Linux; Android 16; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.7977.42 Mobile Safari/537.36", "cpu_frequency": {"max": "1704.0", "min": "324.0"}, "os_version": "16", "build": "BP2A.250705.008", "gpu": {"version": "ARM", "vendor": "ARM", "name": "Immortalis-G925", "opengl_version": "262400"}, "build_prop": {"dalvik_vm_isa_x86_features": "", "dalvik_vm_isa_x86_variant": "", "dalvik_vm_isa_arm_variant": "", "dalvik_vm_isa_arm64_features": "default", "dalvik_vm_isa_arm64_variant": "cortex-a55", "dalvik_vm_isa_arm_features": "", "ro_build_user": "android-build"}, "manufacturer": "Google", "subAgent": "w9el7o79l2f881no92", "local_tz": "IST", "product": "shiba", "brand": "google", "screen_size": "6.3", "mcc": "405", "device_id": str(uuid.uuid4), "mac": "07:78:50:5c:a8:0e", "adid": "9031fb3f-3975-4f23-bf4d-959f1f79476c", "apps_count": {"user_apps": 30, "sideloaded_apps": 7, "stock_apps": 203}, "fingerprint": "google/shiba/shiba:16/BP2A.250705.008/13578956:user/release-keys", "device": "shiba", "sensors": {"magnetometer": {"vendor": "MEMSIC", "name": "MMC56X3X Magnetometer"}, "gyroscope": {"vendor": "Invensense", "name": "ICM45631 Gyroscope"}, "accelerometer": {"vendor": "Invensense", "name": "ICM45631 Accelerometer"}}, "sdk": "36", "name": "shiba", "currency": {"code": "INR", "name": "Indian Rupee"}, "mainboard": "shiba", "country": "India", "local_timezone": "Indian Standard Time", "processor": "AArch64 Processor rev 4 (aarch64)", "network": "WiFi", "carrier": "AirTel", "os_codename": "REL", "cpu_abi": "arm64-v8a", "internal_memory": {"available": "228.83 GB", "shown": "256 GB"}, "model": "Pixel 8", "local_tz_name": "Asia/Kolkata", "resolution": "1080x2400", "display": "BP2A.250705.008", "dpi": "420"}
}


OUT = os.path.join(HERE, "manual_result.json")
APP_TOKEN = "jut9tib0eeps"
PKG = "com.penti.app"
UA_DEFAULT = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
LOG = {}


def log(k, v):
    LOG[k] = v
    print("[%s] %s" % (k, v), flush=True)


def plus0530(ts, ms=0):
    d = (dt.datetime.fromtimestamp(ts, dt.timezone.utc)
         + dt.timedelta(hours=5, minutes=30))
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def ws_bytes(words):
    return b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in words)


def synth_bytes():
    d0, d2, d4 = synth_region()
    assert check(d0, d4)
    return ws_bytes(d0), ws_bytes([d2]), ws_bytes(d4)


def send(method, path, params, blob=None, timeout=25, ua=UA_DEFAULT):
    q = urllib.parse.urlencode(params)
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=timeout)
    if method == "GET":
        conn.putrequest("GET", path + ("?" + q if q else ""), skip_accept_encoding=1)
        conn.putheader("Content-Length", "0")
    else:
        conn.putrequest("POST", path, skip_accept_encoding=1)
        conn.putheader("Content-Type", "application/x-www-form-urlencoded")
        conn.putheader("Content-Length", str(len(q.encode())))
    conn.putheader("Client-SDK", "android5.7.0")
    if blob:
        conn.putheader("Authorization", F.auth_header(blob))
    conn.putheader("User-Agent", ua)
    conn.putheader("Accept-Encoding", "identity")
    conn.endheaders()
    if method == "POST":
        conn.send(q.encode())
    r = conn.getresponse()
    out = (r.status, r.read().decode("utf-8", "replace"))
    conn.close()
    return out


def map_device(dev, gps, auid, now):
    dm = dev.get("display_metrics") or {}
    loc = dev.get("locale") or {}
    get = lambda *ks: next((dev.get(k) for k in ks if dev.get(k) not in (None, "")), "")
    return {
        "gps_adid": gps, "android_uuid": auid,
        "api_level": str(get("sdk", "api_level") or "31"),
        "app_version": "3.13.9", "app_token": APP_TOKEN,
        "os_name": "android", "os_version": str(get("os_version") or "12"),
        "device_name": get("model", "device") or "moto g42",
        "device_type": get("device_type") or "phone",
        "device_manufacturer": get("manufacturer") or "motorola",
        "environment": "production", "package_name": PKG,
        "hardware_name": str(get("hardware") or "MT6833"),
        "os_build": get("build", "os_incremental") or get("build") or "UP1A.231005.007",
        "language": loc.get("language", "en") or "en",
        "cpu_type": get("cpu_abi") or "arm64-v8a",
        "screen_size": dm.get("screen_layout_name", "normal") or "normal",
        "screen_format": dm.get("screen_layout_format", "long") or "long",
        "screen_density": dm.get("density_dpi", "xxhdpi") or "xxhdpi",
        "display_width": str(dm.get("xpx", "1080") or "1080"),
        "display_height": str(dm.get("ypx", "2237") or "2237"),
        "connectivity_type": "1", "ui_mode": "1", "foreground": "1",
        "tracking_enabled": "1", "gps_adid_src": "service",
        "gps_adid_attempt": "1", "needs_response_details": "1",
        "attribution_deeplink": "1", "offline_mode_enabled": "0",
        "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
        "adj_signing_id": "1500000", "headers_id": "10",
        "native_version": "5.0.0", "algorithm": "adj9",
        "client_sdk": "android5.7.0",
        "initiating_package_name": "com.android.vending",
        "store_name_from_system": "com.android.vending",
        "enqueue_size": "0", "wait_total": "0.0", "wait_time": "0.0",
        "first_error": "0", "last_error": "0", "retry_count": "0",
        "created_at": plus0530(now, 100), "sent_at": plus0530(now, 130),
        "installed_at": plus0530(now - 2, 200), "updated_at": plus0530(now - 2, 200),
        "session_count": "1", "activity_kind": "session", "initiated_by": "sdk",
    }


def main():
    cfg = IN
    ref = cfg.get("referrer", "") or ""
    gps = cfg.get("gaid", "").strip()
    dev = cfg.get("device", {}) or {}
    link = cfg.get("link", "") or ""

    # H8 protocol: fresh GAID + fresh android_uuid for every run.
    # Even if gaid is given, refresh it (server merges identity per IP anyway).
    if not gps and link:
        m = re.search(r"(?:gps_adid|idfa|click_id)=([A-Za-z0-9-]+)", link)
        if m:
            gps = m.group(1)
    if not gps and isinstance(dev, dict):
        gps = dev.get("adid") or dev.get("gps_adid") or dev.get("device_id") or ""
    if not gps:
        print("ERROR: no GAID found. Set `gaid` or `link` or `device.adid` in manual_input.json")
        return
    if not ref and link:
        m = re.search(r"install_callback=([^&]+)", link)
        if m:
            log("click_url", urllib.parse.unquote(m.group(1))[:100])
    # Fire the click if requested (default: use provided referrer as-is)
    if not ref and link:
        marker = cfg.get("creative", "cline_manual")
        log("click/firing", "marker=%s" % marker)
        try:
            import farm_win as fw
            code, ref, hops, url = fw.fire_click(gps, marker, link)
            log("click/result", "http=%s reftag=%s" % (code, (ref or "")[:60]))
            if not ref:
                print("ERROR: click fired but no referrer returned."); return
        except Exception as e:
            log("click", "FAILED %s: %s" % (type(e).__name__, str(e)[:120])); return
    if not ref:
        print("ERROR: no referrer. Set `referrer` in manual_input.json "
              "OR set `fire_click\": true` with `link`.")
        return
    auid = str(uuid.uuid4())
    log("gaid", gps)
    log("auid", auid)
    log("reftag", ref[:70])
    log("device", "%s / Android %s / api %s" % (
        dev.get("model") or dev.get("device") or "?",
        dev.get("os_version") or "?", dev.get("sdk") or "?"))

    ua = dev.get("User-Agent") or UA_DEFAULT

    now = time.time()
    val = map_device(dev, gps, auid, now)
    d0b, d2b, d4b = synth_bytes()
    sec = int(now)
    st, blob, desc, unp = F.make_signature_law(val, "session", second=sec,
                                               d0=d0b, d2=d2b, d4=d4b)
    log("session/mint", "%s #10=%dB blob=%dB" % (st, unp, len(blob)))
    p = dict(val)
    p["ask_in"] = "2000"
    c, b = send("POST", "/session", p, blob, ua=ua)
    log("session/send", "%s %s" % (c, b[:220]))

    time.sleep(2)
    now2 = time.time()
    cv = dict(val)
    cv.update({"activity_kind": "click", "google_play_instant": "0",
               "referrer": ref, "referrer_api": "google",
               "source": "install_referrer", "session_length": "0",
               "subsession_count": "1", "time_spent": "0",
               "created_at": plus0530(now2, 100), "sent_at": plus0530(now2, 130),
               "session_count": "1"})
    sd0, sd2, sd4 = synth_bytes()
    try:
        st2, blob2, _, n2 = F.make_signature_law(cv, "click", second=int(now2),
                                                 d0=sd0, d2=sd2, d4=sd4)
        c2, b2 = send("POST", "/sdk_click", cv, blob2, ua=ua)
        log("sdk_click/send", "%s %s" % (c2, b2[:220]))
    except Exception as e:
        log("sdk_click/send", "%s: %s" % (type(e).__name__, str(e)[:120]))

    booked = False
    for attempt in range(5):
        time.sleep(8 if attempt == 0 else 20)
        now3 = time.time()
        ad0, ad2, ad4 = synth_bytes()
        av = dict(val)
        av.update({"activity_kind": "attribution", "initiated_by": "backend",
                   "created_at": plus0530(now3, 100), "sent_at": plus0530(now3, 130)})
        for k in ("session_count", "installed_at", "updated_at"):
            av.pop(k, None)
        try:
            st3, blob3, _, n3 = F.make_signature_law(
                av, "attribution", second=int(now3), d0=ad0, d2=ad2, d4=ad4)
            c3, b3 = send("GET", "/attribution", av, blob3, ua=ua)
            log("attribution/%d" % attempt, "%s %s" % (c3, b3[:260]))
            if c3 == 200 and "VKM" in b3 and '"network":"Organic"' not in b3:
                booked = True
                log("RESULT", "NON-ORGANIC seen (check tracker/adgroup/creative!)")
                break
        except Exception as e:
            log("attribution/%d" % attempt, "%s: %s" % (type(e).__name__, str(e)[:120]))
    if not booked:
        log("RESULT", "Organic/fallback (expected for crafted polls — "
            "see WALL_A_SLICE_91/97 on why only the device can read a booked verdict)")

    LOG.update({"gps": gps, "auid": auid, "referrer": ref[:80]})
    json.dump(LOG, open(OUT, "w"), indent=1)
    print("\nsaved %s" % OUT, flush=True)


if __name__ == "__main__":
    main()


