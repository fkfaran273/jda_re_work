r"""dev_ab.py — same-window A/B: the DEVICE's own attribution verdict vs our
crafted signature for the SAME install identity.

Procedure (the project's documented "mint-on-demand" trigger, TODAY.md §2):
  1. read pre-state (auid, stored attribution verdict, file mtimes)
  2. wipe AdjustAttribution + AdjustIoActivityState, force-stop, relaunch
     -> the SDK starts a FRESH install: new android_uuid, same gps_adid
  3. wait, read the new state: the device's own verdict for that fresh install
  4. immediately ask /attribution with OUR crafted adj9 signature for the SAME
     gps_adid + the SAME new android_uuid
  5. compare

If (3) is non-organic and (4) is Organic -> the server distinguishes the
signature. If both are the same -> the verdict is server state, signature fine.

Usage: python dev_ab.py
"""
import base64
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as fc

PKG = "/data/data/com.penti.app"
STATE = PKG + "/files/AdjustIoActivityState"
ATTR = PKG + "/files/AdjustAttribution"
GAID = "d016e7e4-fb1c-4d0a-b619-db01f6a6a262"
OUT = os.path.join(HERE, "dev_ab_result.json")
UUID_RE = rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

fc.DEV, fc.UA = dict(fc.MOTO), fc.MOTO_UA
fc.OFF_MINUTES, fc.OFF_LABEL = 330, "+0530"


def su(cmd):
    return subprocess.run(["adb", "shell", '/debug_ramdisk/su -c "%s"' % cmd],
                          capture_output=True).stdout.decode("utf-8", "replace")


def su_file(path):
    r = subprocess.run(["adb", "shell",
                        '/debug_ramdisk/su -c "cat %s | base64"' % path],
                       capture_output=True)
    try:
        return base64.b64decode(r.stdout)
    except Exception:
        return b""


def verdict(buf):
    if not buf:
        return None, None
    m = re.search(rb'\{"tracker_token.{0,500}', buf)
    txt = m.group(0).decode("ascii", "replace") if m else ""
    u = re.search(UUID_RE, buf)
    tok = None
    tm = re.search(rb'"tracker_token":"([^"]+)"', buf)
    if tm:
        tok = tm.group(1).decode()
    return tok, (u.group(0).decode() if u else None)


def read_state(tag):
    st, at = su_file(STATE), su_file(ATTR)
    tok, _ = verdict(at)
    u = re.search(UUID_RE, st)
    au = u.group(0).decode() if u else None
    print("[%s] auid=%s stored_token=%s attr_bytes=%d"
          % (tag, au, tok, len(at)), flush=True)
    m = re.search(rb'\{"tracker_token.{0,500}', at) if at else None
    if m:
        print("    stored: %s" % m.group(0).decode("ascii", "replace")[:300],
              flush=True)
    return au, tok, at.decode("ascii", "replace") if at else ""


def main():
    res = {}
    au0, tok0, raw0 = read_state("pre")
    res["pre"] = {"auid": au0, "token": tok0, "raw": raw0[:800]}
    print("wiping Adjust state + relaunching...", flush=True)
    su("rm -f %s %s" % (STATE, ATTR))
    su("am force-stop com.penti.app")
    time.sleep(2)
    su("am start -n com.penti.app/.ui.main.MainActivity")
    au, tok, raw = None, None, ""
    for i in range(6):
        time.sleep(12)
        au, tok, raw = read_state("post+%ds" % (12 * (i + 1)))
        if tok and au:
            break
    res["post"] = {"auid": au, "token": tok, "raw": raw[:800]}
    if au:
        s, r = fc.api_attribution(GAID, au, "")
        try:
            a = json.loads(r)["attribution"]
            v = "%s / %s / eng=%s / inst=%s" % (
                a.get("tracker_token"), a.get("network"),
                a.get("engagement_time"), a.get("installed_at"))
        except Exception:
            v = "HTTP %s %s" % (s, r[:150])
        print("[crafted same auid %s] %s %s" % (au, s, v), flush=True)
        res["crafted"] = {"auid": au, "http": s, "verdict": v,
                          "body": r[:2000]}
    else:
        print("no auid after wipe (app may not have started)", flush=True)
    json.dump(res, open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()