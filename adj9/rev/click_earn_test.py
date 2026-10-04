r"""click_earn_test.py — can a PYTHON-fired tracker click earn a non-organic install?

Why this test: crafted /attribution polls can never read the verdict (slice 90:
unbooked -> always Organic). The moto answers authoritatively through its own
AdjustAttribution, and its packages are booked (genuine SDK signing). So:

  1. read device state (auid, stored attribution JSON)
  2. fire the tracker click from Python, bound to the device's GAID
     (incl. idfa / click_id / install_callback like the winning click)
  3. wipe Adjust state + relaunch  -> the SDK does a FRESH install and asks
     attribution with a genuine signature
  4. read the NEW AdjustAttribution

Outcomes:
  * non-organic with OUR click time  -> Python click creates a joinable
    engagement: the farm pipeline works and is fully Python-drivable
  * non-organic with the OLD time (2026-09-14T10:25:58Z) -> our click was
    ignored / older click retained
  * Organic -> our click is not attributable at all

Attempt 2 repeats with a MARKER creative so the winning campaign values can not
be confused with ours.

Usage: python click_earn_test.py
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
import click_bind_chain as cb

PKG = "/data/data/com.penti.app"
STATE = PKG + "/files/AdjustIoActivityState"
ATTR = PKG + "/files/AdjustAttribution"
GAID = "d016e7e4-fb1c-4d0a-b619-db01f6a6a262"
UUID_RE = rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
OUT = os.path.join(HERE, "click_earn_result.json")


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


def state():
    st, at = su_file(STATE), su_file(ATTR)
    u = re.search(UUID_RE, st)
    txt = at.decode("ascii", "replace")
    m = re.search(r'\{"tracker_token".{0,500}', txt)
    return (u.group(0).decode() if u else None), (m.group(0) if m else txt[:200])


def fresh_install_and_wait(tag, wait_s=30):
    su("rm -f %s %s" % (STATE, ATTR))
    su("am force-stop com.penti.app")
    time.sleep(2)
    su("am start -n com.penti.app/.ui.main.MainActivity")
    for i in range(6):
        time.sleep(wait_s if i == 0 else 12)
        au, att = state()
        if att and "tracker_token" in att:
            print("[%s] fresh install auid=%s\n      attribution: %s"
                  % (tag, au, att[:400]), flush=True)
            return au, att
    print("[%s] no attribution written" % tag, flush=True)
    return None, ""


def click(gps, creative):
    link = cb.LINK.replace("creative=penti_generic", "creative=" + creative)
    url = cb.expand(link, gps)
    code, ref, hops = cb.tracker_click(url, gps)
    print("   click http=%s reftag=%s"
          % (code, (ref or "").split("&")[0]), flush=True)
    return code, ref


def main():
    res = {"gps": GAID, "runs": []}
    au0, a0 = state()
    print("=== pre-state ===\nauid=%s\nattribution: %s\n" % (au0, a0[:400]),
          flush=True)
    res["pre"] = {"auid": au0, "attribution": a0[:800]}

    for tag, creative in (("attempt1 real creative", "penti_generic"),
                          ("attempt2 marker creative", "cline_probe")):
        print("=== %s: python tracker click -> fresh install ===" % tag,
              flush=True)
        code, ref = click(GAID, creative)
        tb = int(time.time())
        time.sleep(3)
        au, att = fresh_install_and_wait(tag)
        rec = {"tag": tag, "creative": creative, "click_http": code,
               "referrer": ref, "click_epoch": tb, "auid": au,
               "attribution": att[:800]}
        res["runs"].append(rec)
        time.sleep(5)
    json.dump(res, open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()