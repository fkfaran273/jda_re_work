"""hyp_run2.py - H9 test: EXACT 45-key device wire body + lawful blob.

Hypothesis H9: the /session body must carry exactly the device's 45 keys (order
preserved from the wire template). The 18 missing wired keys are breaking server
claim extraction -> unmatched signed set -> Organic fallback.

Arm h9: fresh GAID -> click from device -> Python session from PC with the exact
45-key body (values from our session map + wire-template constants) -> read via app.
"""
import base64
import datetime as dt
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
H.SERIAL = "ZD2228MY3X"
from region_synth import synth_region, check

OUT = os.path.join(HERE, "hyp_h9.json")
WIRE45 = ["android_uuid", "api_level", "app_token", "app_version",
    "attribution_deeplink", "connectivity_type", "cpu_type", "created_at",
    "device_manufacturer", "device_name", "device_type", "display_height",
    "display_width", "enqueue_size", "environment", "first_error",
    "foreground", "gps_adid", "gps_adid_attempt", "gps_adid_src",
    "hardware_name", "initiating_package_name", "installed_at", "language",
    "last_error", "mcc", "mnc", "needs_response_details",
    "offline_mode_enabled", "os_build", "os_name", "os_version",
    "package_name", "retry_count", "screen_density", "screen_format",
    "screen_size", "sent_at", "session_count", "store_name_from_system",
    "tracking_enabled", "ui_mode", "updated_at", "wait_time", "wait_total"]

CONST = {"enqueue_size": "0", "first_error": "0", "last_error": "0",
         "retry_count": "0", "wait_time": "0.0", "wait_total": "0.0",
         "mcc": "405", "mnc": "872"}


def plus0530(ts, ms=0):
    d = (dt.datetime.fromtimestamp(ts, dt.timezone.utc)
         + dt.timedelta(hours=5, minutes=30))
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def main():
    out = {"arm": "h9"}
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    H.set_gaid(gps)
    H.wipe_app()
    out["gps"] = gps
    print("[gaid] fresh=%s" % gps, flush=True)

    raw = H.su("cat /data/data/com.penti.app/files/AdjustAttribution 2>/dev/null || echo NOFILE")
    print("[h8] pre-read empty: %s" % ("tracker_token" not in raw), flush=True)

    code, ref = H.click(True, gps)
    print("[click] %s %s" % (code, (ref or "")[:60]), flush=True)

    now = time.time()
    val = {
        "gps_adid": gps, "android_uuid": auid,
        "api_level": "31", "app_version": "3.13.9",
        "app_token": "jut9tib0eeps",
        "os_name": "android", "os_version": "12",
        "device_name": "moto g42", "device_type": "phone",
        "device_manufacturer": "motorola",
        "environment": "production",
        "package_name": "com.penti.app",
        "hardware_name": "S2SE32.28-28-4",
        "os_build": "S2SE32.28-28-4",
        "language": "tr", "cpu_type": "arm64-v8a",
        "screen_size": "normal", "screen_format": "long",
        "screen_density": "high",
        "display_width": "1080", "display_height": "2237",
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
    val.update(CONST)
    sec = int(now)
    d0, d2, d4 = synth_region()
    assert check(d0, d4)
    wb = lambda ws: b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in ws)
    st, blob, desc, unp = F.make_signature_law(val, "session", second=sec,
                                               d0=wb(d0), d2=wb([d2]), d4=wb(d4))
    assert all(k in val and val[k] not in (None, "") for k in WIRE45), "wire keys"
    p = {k: val[k] for k in WIRE45}   # EXACT device body, no extras, no omissions
    q = urllib.parse.urlencode(p)
    auth = F.auth_header(blob)
    import http.client
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=25)
    conn.putrequest("POST", "/session", skip_accept_encoding=1)
    conn.putheader("Content-Type", "application/x-www-form-urlencoded")
    conn.putheader("Content-Length", str(len(q.encode())))
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth)
    conn.putheader("User-Agent", H.UA)
    conn.putheader("Accept-Encoding", "identity")
    conn.endheaders()
    conn.send(q.encode())
    r = conn.getresponse()
    out["session"] = [r.status, r.read().decode("utf-8", "replace")[:200]]
    conn.close()
    print("[session/h9] %s" % (out["session"],), flush=True)

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
