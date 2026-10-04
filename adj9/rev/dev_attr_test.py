r"""dev_attr_test.py — the decisive A/B: crafted /attribution with the DEVICE's own
android_uuid vs a fresh one (same gps_adid, same minute, same signature maker).

Device state (dev_state.py, 2026-09-15):
  adid 2fedfd3dfcc48e92aae70f3fd2e1608a  (GAID d016e7e4-fb1c-4d0a-b619-db01f6a6a262)
  uuid 41ca78c9-f652-4555-a546-dbe7999efbec   <- the install's own auid
  stored AdjustAttribution = 24pxw9rl VKM Digital Yeni::AH::vkm_0926_36::penti_generic

Every offline attempt so far minted a FRESH auid, i.e. asked about a brand-new
install record (always Organic). This script asks about the real one.

Variants: device uuid / fresh uuid / 7ba51fce (an auid that answered VKM live).

Usage: python dev_attr_test.py
"""
import base64
import json
import os
import re
import subprocess
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as fc

STATE = "/data/data/com.penti.app/files/AdjustIoActivityState"
ATTR = "/data/data/com.penti.app/files/AdjustAttribution"
GAID = "d016e7e4-fb1c-4d0a-b619-db01f6a6a262"
OUT = os.path.join(HERE, "dev_attr_test_result.json")
UUID_RE = rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
ADID_RE = rb"\b[0-9a-f]{32}\b"

# the moto identity: the device is +0530, api 31, os 12
fc.DEV, fc.UA = dict(fc.MOTO), fc.MOTO_UA
fc.OFF_MINUTES, fc.OFF_LABEL = 330, "+0530"


def su_b64(path):
    r = subprocess.run(["adb", "shell",
                        '/debug_ramdisk/su -c "cat %s | base64"' % path],
                       capture_output=True)
    try:
        return base64.b64decode(r.stdout)
    except Exception:
        return b""


def device_ids():
    st = su_b64(STATE)
    at = su_b64(ATTR)
    uuids = [m.group(0).decode() for m in re.finditer(UUID_RE, st)]
    adids = [m.group(0).decode() for m in re.finditer(ADID_RE, st)]
    resp = ""
    m = re.search(rb'\{\\?"tracker_token.{0,600}', at)
    if m:
        resp = m.group(0).decode("ascii", "replace")
    return {"auids": uuids, "adids": adids, "attr_raw": resp}


def main():
    info = device_ids()
    auid_dev = info["auids"][0] if info["auids"] else None
    print("device adid(s): %s" % info["adids"], flush=True)
    print("device auid(s): %s" % info["auids"], flush=True)
    print("stored attribution: %s" % info["attr_raw"][:400], flush=True)

    variants = [("device auid (41ca78c9)", auid_dev),
                ("fresh auid", str(uuid.uuid4())),
                ("auid 7ba51fce (VKM live)", "7ba51fce-9d49-46ec-94d3-924e8a0ff269")]
    res = {"device_auids": info["auids"], "device_adids": info["adids"],
           "stored_attribution": info["attr_raw"], "runs": []}
    for label, au in variants:
        if not au:
            continue
        s, r = fc.api_attribution(GAID, au, "")
        try:
            a = json.loads(r)["attribution"]
            v = "%s / %s / eng=%s / inst=%s" % (
                a.get("tracker_token"), a.get("network"),
                a.get("engagement_time"), a.get("installed_at"))
        except Exception:
            v = "HTTP %s %s" % (s, r[:150])
        print("[%s] auid=%s -> %s %s" % (label, au, s, v), flush=True)
        res["runs"].append({"label": label, "auid": au, "http": s,
                            "verdict": v, "body": r[:2000]})
    json.dump(res, open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()