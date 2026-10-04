"""attr_exact.py - THE exact 22-param /attribution call the device sends.

From the device wire dump, /attribution carries EXACTLY 22 query params (in this
order). Every prior Python arm sent ~50. Run: python -X utf8 attr_exact.py <gps> [referrer]
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

OUT = os.path.join(HERE, "attr_exact_result.json")
LOG = {}

ATTR_PARAMS = [
    "initiated_by", "gps_adid_attempt", "api_level", "app_version",
    "app_token", "os_version", "created_at", "device_type", "gps_adid",
    "foreground", "android_uuid", "sent_at", "offline_mode_enabled",
    "device_name", "environment", "needs_response_details",
    "attribution_deeplink", "package_name", "os_name", "ui_mode",
    "gps_adid_src", "tracking_enabled",
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
    gps = sys.argv[1] if len(sys.argv) > 1 else None
    ref = sys.argv[2] if len(sys.argv) > 2 else None
    if not gps:
        print("usage: python -X utf8 attr_exact.py <gps_adid> [referrer]")
        return
    auid = str(uuid.uuid4())
    log("gaid", gps)
    log("auid", auid)
    if ref:
        log("referrer", ref[:70])

    now = time.time()
    sec = int(now)
    val = {
        "initiated_by": "backend",
        "gps_adid_attempt": "1",
        "api_level": "31",
        "app_version": "3.13.9",
        "app_token": "jut9tib0eeps",
        "os_version": "12",
        "created_at": plus0530(now, 100),
        "device_type": "phone",
        "gps_adid": gps,
        "foreground": "1",
        "android_uuid": auid,
        "sent_at": plus0530(now, 130),
        "offline_mode_enabled": "0",
        "device_name": "moto g42",
        "environment": "production",
        "needs_response_details": "1",
        "attribution_deeplink": "1",
        "package_name": "com.penti.app",
        "os_name": "android",
        "ui_mode": "1",
        "gps_adid_src": "service",
        "tracking_enabled": "1",
        "activity_kind": "attribution",
        "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
        "adj_signing_id": "1500000", "headers_id": "10",
        "native_version": "5.0.0", "algorithm": "adj9",
        "client_sdk": "android5.7.0",
    }
    d0b, d2b, d4b = synth_bytes()
    st, blob, desc, unp = F.make_signature_law(val, "attribution", second=sec,
                                               d0=d0b, d2=d2b, d4=d4b)
    log("mint", "%s #10=%dB blob=%dB" % (st, unp, len(blob)))

    p = {k: val[k] for k in ATTR_PARAMS if k in val}
    log("params", "%d keys (device-exact)" % len(p))
    c, b = send("GET", "/attribution", p, blob)
    log("attribution", "%s %s" % (c, b[:400]))

    json.dump(LOG, open(OUT, "w"), indent=1)
    print("saved", OUT)


if __name__ == "__main__":
    main()

