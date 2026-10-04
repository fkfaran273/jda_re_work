"""hyp_run3.py - H11: EXACT device request replication (body order + headers).

From the real device wire dump, the app's session request is:
  Client-SDK, Authorization, Content-Type, User-Agent, Host, Connection: Keep-Alive,
  Accept-Encoding: gzip, Content-Length
  body = 43 keys in the SDK's Java-HashMap iteration order (NOT alphabetical),
         with NO mcc/mnc, NO activity_kind, NO initiated_by, NO ask_in.
"""
import datetime as dt
import gzip
import http.client
import io
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
import hyp_lib as H
from region_synth import synth_region, check

OUT = os.path.join(HERE, "hyp_h11.json")

DEV_ORDER = [
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
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"


def plus0530(ts, ms=0):
    d = (dt.datetime.fromtimestamp(ts, dt.timezone.utc)
         + dt.timedelta(hours=5, minutes=30))
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def main():
    out = {"arm": "h11"}
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    H.set_gaid(gps)
    H.wipe_app()
    out["gps"] = gps
    print("[gaid] fresh=%s" % gps, flush=True)

    code, ref = H.click(True, gps)
    print("[click] %s" % code, flush=True)

    now = time.time()
    vals = {
        "store_name_from_system": "com.android.vending",
        "gps_adid_attempt": "1", "api_level": "31",
        "hardware_name": "S2SE32.28-28-4", "app_version": "3.13.9",
        "app_token": "jut9tib0eeps", "installed_at": plus0530(now - 2, 200),
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
    }
    sign_map = dict(vals)
    sign_map.update({
        "activity_kind": "session",
        "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
        "adj_signing_id": "1500000", "headers_id": "10",
        "native_version": "5.0.0", "algorithm": "adj9",
        "client_sdk": "android5.7.0",
    })
    sec = int(now)
    d0, d2, d4 = synth_region()
    assert check(d0, d4)
    wb = lambda ws: b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in ws)
    st, blob, desc, unp = F.make_signature_law(sign_map, "session", second=sec,
                                               d0=wb(d0), d2=wb([d2]), d4=wb(d4))
    print("[mint] %s #10=%dB blob=%dB" % (st, unp, len(blob)), flush=True)

    body = "&".join("%s=%s" % (k, urllib.parse.quote(str(vals[k]), safe=""))
                    for k in DEV_ORDER)
    body_b = body.encode()
    auth = F.auth_header(blob)

    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=25)
    conn.putrequest("POST", "/session", skip_host=1, skip_accept_encoding=1)
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth)
    conn.putheader("Content-Type", "application/x-www-form-urlencoded")
    conn.putheader("User-Agent", UA)
    conn.putheader("Host", "app.adjust.com")
    conn.putheader("Connection", "Keep-Alive")
    conn.putheader("Accept-Encoding", "gzip")
    conn.putheader("Content-Length", str(len(body_b)))
    conn.endheaders()
    conn.send(body_b)
    r = conn.getresponse()
    raw = r.read()
    if r.getheader("Content-Encoding") == "gzip":
        try:
            raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
        except Exception:
            pass
    resp = raw.decode("utf-8", "replace")
    out["session"] = [r.status, resp[:200]]
    print("[session/h11] %d %s" % (r.status, resp[:200]), flush=True)
    conn.close()

    v = H.app_read_verdict(gps)
    out["verdict"] = v
    if v:
        print("[verdict] token=%s network=%s" % (v.get("tracker_token"),
                                                 v.get("network")), flush=True)
        print("=> %s" % ("BOOKED NON-ORGANIC!" if v.get("network") != "Organic"
                          else "ORGANIC"), flush=True)
    else:
        print("[verdict] none", flush=True)
    json.dump(out, open(OUT, "w"), indent=1)


if __name__ == "__main__":
    main()


