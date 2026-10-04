"""hyp_run.py - run ONE hypothesis arm end to end.

Usage: python hyp_run.py h1 | h2 | h1b
  h1 : device click + Python session sent from PC
  h2 : device click + Python session sent from DEVICE (adb curl)
  h1b: pc click     + Python session sent from device (IP-mismatch control)

Every arm: fresh GAID + H8 pre-read (must show no record) + click FIRST +
Python-signed session (lawful region) + app-side verdict read.
"""
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


def plus0530(ts, ms=0):
    d = (dt.datetime.fromtimestamp(ts, dt.timezone.utc)
         + dt.timedelta(hours=5, minutes=30))
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def session_map(gps, auid, now):
    return {
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


def main():
    arm = sys.argv[1] if len(sys.argv) > 1 else "h1"
    out = {"arm": arm}
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    H.set_gaid(gps)
    H.wipe_app()
    out["gps"] = gps
    print("[gaid] fresh=%s" % gps, flush=True)

    raw = H.su("cat /data/data/com.penti.app/files/AdjustAttribution 2>/dev/null || echo NOFILE")
    out["pre_read_empty"] = ("tracker_token" not in raw)
    print("[h8] pre-read empty: %s" % out["pre_read_empty"], flush=True)

    code, ref = H.click(arm in ("h1", "h2"), gps)
    out["click"] = {"code": code, "reftag": (ref or "")[:60],
                    "from": "device" if arm in ("h1", "h2") else "pc"}
    print("[click] %s %s" % (code, (ref or "")[:60]), flush=True)

    now = time.time()
    val = session_map(gps, auid, now)
    d0b, d2b, d4b = H.synth_bytes()
    sec = int(now)
    st, blob, desc, unp = F.make_signature_law(val, "session", second=sec,
                                               d0=d0b, d2=d2b, d4=d4b)
    p = dict(val)
    p["ask_in"] = "2000"
    q = urllib.parse.urlencode(p)
    auth = F.auth_header(blob)
    if arm == "h1":
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
    else:
        import base64
        b64 = base64.b64encode(q.encode()).decode()
        h = auth.replace("'", "")
        cp = ("echo %s | base64 -d > /data/local/tmp/h_sess.txt; "
              "curl -s -w 'C:%%{http_code}' -X POST 'https://app.adjust.com/session' "
              "-H 'Client-SDK: android5.7.0' -H 'Authorization: %s' "
              "-H 'User-Agent: %s' -H 'Content-Type: application/x-www-form-urlencoded' "
              "--data-binary @/data/local/tmp/h_sess.txt" % (b64, h, H.UA))
        out["session"] = ["device", H.su(cp)[-160:]]
    print("[session] %s" % (out["session"],), flush=True)

    v = H.app_read_verdict(gps)
    out["verdict"] = v
    if v:
        print("[verdict] token=%s network=%s" % (v.get("tracker_token"),
                                                 v.get("network")), flush=True)
        print("=> %s" % ("BOOKED NON-ORGANIC" if v.get("network") != "Organic"
                          else "ORGANIC"), flush=True)
    else:
        print("[verdict] none", flush=True)
    json.dump(out, open(os.path.join(HERE, "hyp_%s.json" % arm), "w"), indent=1)


if __name__ == "__main__":
    main()

