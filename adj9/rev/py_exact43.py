"""py_exact43.py - EXACT 43-param session body (device-identical) + lawful blob.

The device's /session carries 43 params (from the wire dump). This sends ALL 43
in the device's exact order + our lawful region, then reads /attribution.
"""
import datetime as dt
import http.client
import json
import os
import struct
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
from region_synth import synth_region, check

OUT = os.path.join(HERE, "exact43_result.json")
LOG = {}

PARAM_ORDER = [
    "store_name_from_system", "gps_adid_attempt", "api_level", "hardware_name",
    "app_version", "app_token", "installed_at", "created_at", "wait_total",
    "device_type", "language", "gps_adid", "foreground", "connectivity_type",
    "device_manufacturer", "display_width", "device_name",
    "needs_response_details", "os_build", "updated_at", "cpu_type",
    "retry_count", "screen_size", "screen_format", "last_error",
    "gps_adid_src", "wait_time", "os_version", "first_error", "android_uuid",
    "sent_at", "offline_mode_enabled", "environment", "screen_density",
    "attribution_deeplink", "session_count", "display_height", "package_name",
    "initiating_package_name", "os_name", "ui_mode", "enqueue_size",
    "tracking_enabled",
]


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


def send(method, path, params, blob=None, timeout=25):
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
    conn.putheader("User-Agent",
                   "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)")
    conn.putheader("Accept-Encoding", "identity")
    conn.endheaders()
    if method == "POST":
        conn.send(q.encode())
    r = conn.getresponse()
    out = (r.status, r.read().decode("utf-8", "replace"))
    conn.close()
    return out


def main():
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    log("identity", "gps=%s auid=%s" % (gps, auid))
    now = time.time()
    val = {
        "store_name_from_system": "com.android.vending",
        "gps_adid_attempt": "1", "api_level": "31",
        "hardware_name": "S2SE32.28-28-4", "app_version": "3.13.9",
        "app_token": "jut9tib0eeps",
        "installed_at": plus0530(now - 2, 200),
        "created_at": plus0530(now, 100), "wait_total": "0.0",
        "device_type": "phone", "language": "tr", "gps_adid": gps,
        "foreground": "1", "connectivity_type": "1",
        "device_manufacturer": "motorola", "display_width": "1080",
        "device_name": "moto g42", "needs_response_details": "1",
        "os_build": "S2SE32.28-28-4", "updated_at": plus0530(now - 2, 200),
        "cpu_type": "arm64-v8a", "retry_count": "0", "screen_size": "normal",
        "screen_format": "long", "last_error": "0", "gps_adid_src": "service",
        "wait_time": "0.0", "os_version": "12", "first_error": "0",
        "android_uuid": auid, "sent_at": plus0530(now, 130),
        "offline_mode_enabled": "0", "environment": "production",
        "screen_density": "high", "attribution_deeplink": "1",
        "session_count": "1", "display_height": "2237",
        "package_name": "com.penti.app",
        "initiating_package_name": "com.android.vending",
        "os_name": "android", "ui_mode": "1", "enqueue_size": "0",
        "tracking_enabled": "1",
        "activity_kind": "session",
        "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
        "adj_signing_id": "1500000", "headers_id": "10",
        "native_version": "5.0.0", "algorithm": "adj9",
        "client_sdk": "android5.7.0",
    }
    sec = int(now)
    d0b, d2b, d4b = synth_bytes()
    st, blob, desc, unp = F.make_signature_law(val, "session", second=sec,
                                               d0=d0b, d2=d2b, d4=d4b)
    log("mint", "%s #10=%dB blob=%dB" % (st, unp, len(blob)))
    p = {k: val[k] for k in PARAM_ORDER}
    log("params", "%d keys (device-exact order)" % len(p))
    c, b = send("POST", "/session", p, blob)
    log("session", "%s %s" % (c, b[:300]))

    time.sleep(3)
    now2 = time.time()
    attr = {
        "initiated_by": "backend", "gps_adid_attempt": "1", "api_level": "31",
        "app_version": "3.13.9", "app_token": "jut9tib0eeps", "os_version": "12",
        "created_at": plus0530(now2, 100), "device_type": "phone",
        "gps_adid": gps, "foreground": "1", "android_uuid": auid,
        "sent_at": plus0530(now2, 130), "offline_mode_enabled": "0",
        "device_name": "moto g42", "environment": "production",
        "needs_response_details": "1", "attribution_deeplink": "1",
        "package_name": "com.penti.app", "os_name": "android", "ui_mode": "1",
        "gps_adid_src": "service", "tracking_enabled": "1",
        "activity_kind": "attribution",
        "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
        "adj_signing_id": "1500000", "headers_id": "10",
        "native_version": "5.0.0", "algorithm": "adj9", "client_sdk": "android5.7.0",
    }
    ad0, ad2, ad4 = synth_bytes()
    st3, blob3, _, _ = F.make_signature_law(attr, "attribution", second=int(now2),
                                            d0=ad0, d2=ad2, d4=ad4)
    c3, b3 = send("GET", "/attribution", attr, blob3)
    log("attribution", "%s %s" % (c3, b3[:400]))

    json.dump(LOG, open(OUT, "w"), indent=1)
    print("saved", OUT)


if __name__ == "__main__":
    main()
