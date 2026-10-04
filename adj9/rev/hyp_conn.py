"""hyp_conn.py - H10: /session AND /attribution on the SAME HTTPS connection.

The app sends session → gets response → sends attribution on the SAME persistent
connection. Every Python test used separate connections. This arm replicates the
app's connection-reuse pattern.
"""
import base64
import datetime as dt
import http.client
import json
import os
import re
import struct
import subprocess
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
import hyp_lib as H
from region_synth import synth_region, check

OUT = os.path.join(HERE, "hyp_h10.json")
UA = "Dalvik/2.1.0 (Linux; U; Android 13; KB2001 Build/SKQ1.211103.001)"


def plus0530(ts, ms=0):
    d = (dt.datetime.fromtimestamp(ts, dt.timezone.utc)
         + dt.timedelta(hours=5, minutes=30))
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def main():
    out = {"arm": "h10"}
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    H.set_gaid(gps)
    H.wipe_app()
    out["gps"] = gps
    print("[gaid] fresh=%s" % gps, flush=True)

    code, ref = H.click(True, gps)
    print("[click] %s" % code, flush=True)
    time.sleep(1)

    now = time.time()
    val = {
        "gps_adid": gps, "android_uuid": auid,
        "api_level": "33", "app_version": "3.13.9",
        "app_token": "jut9tib0eeps",
        "os_name": "android", "os_version": "13",
        "device_name": "KB2001", "device_type": "phone",
        "device_manufacturer": "OnePlus",
        "environment": "production",
        "package_name": "com.penti.app",
        "hardware_name": "qcom",
        "os_build": "KB2001_11_C.50",
        "language": "en", "cpu_type": "arm64-v8a",
        "screen_size": "normal", "screen_format": "long",
        "screen_density": "xxhdpi",
        "display_width": "1080", "display_height": "2400",
        "connectivity_type": "1", "ui_mode": "1", "foreground": "1",
        "tracking_enabled": "1",
        "gps_adid_src": "service", "gps_adid_attempt": "1",
        "needs_response_details": "1",
        "attribution_deeplink": "1",
        "offline_mode_enabled": "0",
        "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
        "adj_signing_id": "1500000",
        "headers_id": "10",
        "native_version": "5.0.0",
        "algorithm": "adj9",
        "client_sdk": "android5.7.0",
        "initiating_package_name": "com.android.vending",
        "store_name_from_system": "com.android.vending",
        "created_at": plus0530(now, 100), "sent_at": plus0530(now, 130),
        "installed_at": plus0530(now - 2, 200),
        "updated_at": plus0530(now - 2, 200),
        "session_count": "1", "activity_kind": "session",
        "initiated_by": "sdk",
    }
    sec = int(now)
    d0, d2, d4 = synth_region()
    assert check(d0, d4)
    wb = lambda ws: b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in ws)
    st_s, blob_s, _, _ = F.make_signature_law(val, "session", second=sec,
                                              d0=wb(d0), d2=wb([d2]), d4=wb(d4))

    # SAME connection: session + attribution back-to-back
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    q = urllib.parse.urlencode(val)
    auth_s = F.auth_header(blob_s)
    conn.putrequest("POST", "/session", skip_accept_encoding=1)
    conn.putheader("Content-Type", "application/x-www-form-urlencoded")
    conn.putheader("Content-Length", str(len(q.encode())))
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth_s)
    conn.putheader("User-Agent", UA)
    conn.putheader("Accept-Encoding", "identity")
    conn.endheaders()
    conn.send(q.encode())
    r = conn.getresponse()
    body_s = r.read().decode("utf-8", "replace")
    print("[session] %d %s" % (r.status, body_s[:200]), flush=True)
    out["session"] = [r.status, body_s[:200]]

    # attribution on the SAME connection (keep-alive)
    time.sleep(2)  # the app waits ask_in ms
    now2 = time.time()
    av = {k: val[k] for k in val if k != "ask_in"}
    av.update({"activity_kind": "attribution", "initiated_by": "backend",
               "created_at": plus0530(now2, 100), "sent_at": plus0530(now2, 130)})
    for k in ("session_count", "installed_at", "updated_at",
              "initiating_package_name", "store_name_from_system"):
        av.pop(k, None)
    sec2 = int(now2)
    d0a, d2a, d4a = synth_region()
    assert check(d0a, d4a)
    st_a, blob_a, _, _ = F.make_signature_law(av, "attribution", second=sec2,
                                              d0=wb(d0a), d2=wb([d2a]), d4=wb(d4a))
    qa = urllib.parse.urlencode(av)
    auth_a = F.auth_header(blob_a)
    conn.putrequest("GET", "/attribution?" + qa, skip_accept_encoding=1)
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth_a)
    conn.putheader("User-Agent", UA)
    conn.putheader("Accept-Encoding", "identity")
    conn.endheaders()
    r2 = conn.getresponse()
    body_a = r2.read().decode("utf-8", "replace")
    print("[attribution] %d %s" % (r2.status, body_a[:300]), flush=True)
    out["attribution"] = [r2.status, body_a[:300]]
    conn.close()

    # read via app
    v = H.app_read_verdict(gps)
    out["verdict"] = v
    if v:
        print("[verdict] token=%s network=%s" % (v.get("tracker_token"),
                                                 v.get("network")), flush=True)
        print("=> %s" % ("BOOKED NON-ORGANIC" if v.get("network") != "Organic"
                          else "ORGANIC"), flush=True)
    else:
        print("[verdict] none", flush=True)
    json.dump(out, open(OUT, "w"), indent=1)


if __name__ == "__main__":
    main()
