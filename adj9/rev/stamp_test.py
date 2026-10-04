r"""stamp_test.py — does the BODY's timestamp timezone have to match the wire?

The maker writes the body's created/installed/updated stamps in the base
capture's timezone (+0200) and merely re-points them to the request's instant:
    d10 = d10.replace(<base created>, created.replace(b"+0530", b"+0200"))
i.e. every crafted body so far carries the RIGHT INSTANT IN THE WRONG TZ
("keep +0200 in body, cleartext uses +0530", tracker_chain2.py). That was
justified by HTTP 200s — but 200 is the envelope gate, not the booking gate.

Live oracle: the moto (gps d016e7e4) is currently NON-ORGANIC (24pxw9rl) after
the dev_ab.py wipe, while our crafted /attribution answers Organic. So:

  v1  stamps in +0200   (current maker behaviour)
  v2  stamps in +0530   (byte-consistent with the request's own stamps)

If v2 books (VKM 24pxw9rl) the mismatch was the missing piece.

Usage: python stamp_test.py
"""
import base64
import json
import os
import re
import struct
import subprocess
import sys
import time
import uuid
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as fc
from fin_vm2 import FinEx
from header_gen import make_header

GOODZERO, HRAND = fc.ZERO0, fc.HRAND
D = fc.D
ORDER = fc.ORDER
STATE = "/data/data/com.penti.app/files/AdjustIoActivityState"
GAID = "d016e7e4-fb1c-4d0a-b619-db01f6a6a262"
UUID_RE = rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
OUT = os.path.join(HERE, "stamp_test_result.json")

fc.DEV, fc.UA = dict(fc.MOTO), fc.MOTO_UA
fc.OFF_MINUTES, fc.OFF_LABEL = 330, "+0530"


def device_auid():
    r = subprocess.run(["adb", "shell",
                        '/debug_ramdisk/su -c "cat %s | base64"' % STATE],
                       capture_output=True)
    try:
        d = base64.b64decode(r.stdout)
    except Exception:
        return None
    m = re.search(UUID_RE, d)
    return m.group(0).decode() if m else None


def mint(second, created, gps, auid, installed, wire_tz):
    """Copy of fc.make_signature with a `wire_tz` switch on the body stamps."""
    by = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"]))
          for d in D["descs"]}
    if HRAND:
        import secrets
        by[4] = (8, secrets.token_bytes(32))
    if GOODZERO:
        by[0] = (36, bytes(144))
    cre = created if wire_tz else created.replace(b"+0530", b"+0200")
    ins = installed if wire_tz else installed.replace(b"+0530", b"+0200")
    d10 = by[10][1].replace(b"2026-09-12T21:15:11.678Z+0200", cre)
    if gps:
        d10 = fc.swap_eq(d10, b"f476b3d4-e0b1-4707-bc43-6153d17f7f8c",
                         gps.encode())
    if auid:
        d10 = fc.swap_eq(d10, b"d773f47f-fc0e-4994-9cf7-7c3cf5bb6368",
                         auid.encode())
    d10 = fc.rep1(d10, b"moto g42", fc.DEV["device_name"].encode())
    d10 = fc.rep1(d10, b"S2SE32.28-28-4", fc.DEV["hardware_name"].encode())
    d10 = fc.rep1(d10, b"S2SE32.28-28-4", fc.DEV["os_build"].encode())
    d10 = fc.swap_eq(d10, b"12com.penti.app",
                     (fc.DEV["os_version"] + "com.penti.app").encode())
    d10 = fc.swap_eq(d10, b"31jut9tib0eeps",
                     (fc.DEV["api_level"] + "jut9tib0eeps").encode())
    if installed:
        d10 = fc.swap_eq(d10, b"2026-09-08T12:20:49.782Z+0200", ins)
        d10 = fc.swap_eq(d10, b"2026-09-10T07:26:18.015Z+0200", ins)
    by[7] = (1, struct.pack(">I", len(d10)))
    by[10] = (len(d10) // 4, d10)
    ex = FinEx(second, [(by[i][0], 0, by[i][1]) for i in ORDER])
    status = ex.run(max_steps=20_000_000)
    sinks = defaultdict(dict)
    for (s, n, v) in ex.emit_trace:
        sinks[s][n] = v
    blob = b"".join(struct.pack(">I", sinks[0x5500000000].get(i, 0))
                    for i in range(48))
    assert blob[:16] == make_header(second)
    return status, ex.steps, blob, d10


def send_attr(blob, sec):
    """/attribution GET with OUR blob (fc.api_attribution would mint its own)."""
    p = {"initiated_by": "backend", "gps_adid_attempt": "1",
         "api_level": fc.DEV["api_level"], "app_version": fc.DEV["app_version"],
         "app_token": fc.APP_TOKEN, "os_version": fc.DEV["os_version"],
         "created_at": fc.fmt(sec - 1, 666).decode(), "device_type": "phone",
         "gps_adid": GAID, "foreground": "1", "android_uuid": AUID_OUT[0],
         "sent_at": fc.fmt(sec - 1, 696).decode(), "offline_mode_enabled": "0",
         "device_name": fc.DEV["device_name"], "environment": "production",
         "needs_response_details": "1", "attribution_deeplink": "1",
         "package_name": "com.penti.app", "os_name": "android",
         "ui_mode": "1", "gps_adid_src": "service", "tracking_enabled": "1"}
    return fc.send("https://app.adjust.com/attribution", p, blob,
                   method="GET")


AUID_OUT = [None]


def main():
    auid = device_auid()
    AUID_OUT[0] = auid
    print("device auid: %s" % auid, flush=True)
    res = {"auid": auid, "runs": []}
    for label, wire_tz in (("v1 body stamps +0200 (current maker)", False),
                           ("v2 body stamps +0530 (wire-matched)", True)):
        sec = int(time.time()) + 35
        cre = fc.fmt(sec - 1, 666)
        ins = fc.fmt(sec - 170, 774)
        st, steps, blob, d10 = mint(sec, cre, GAID, auid, ins, wire_tz)
        print("[%s] mint %s steps=%s" % (label, st, steps), flush=True)
        s, r = send_attr(blob, sec)
        try:
            a = json.loads(r)["attribution"]
            v = "%s / %s / eng=%s" % (a.get("tracker_token"),
                                      a.get("network"),
                                      a.get("engagement_time"))
        except Exception:
            v = "HTTP %s %s" % (s, r[:150])
        print("   -> %s %s" % (s, v), flush=True)
        res["runs"].append({"label": label, "wire_tz": wire_tz, "http": s,
                            "verdict": v, "body": r[:1500]})
        time.sleep(3)
    json.dump(res, open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()