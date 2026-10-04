r"""farm_win.py — the operational script: DRIVE ONE INSTALL FROM DEVICE DATA + A
CLICKED LINK, and read the verdict the way the server actually answers (on the
device), not with a crafted poll.

Input = exactly what you can supply:
  * device data JSON (the clicker's dump: adid / device_id / model / api ...)
  * the clicked link (or an already-clicked referrer + reftag)
  * an adb-connected rooted device (the app must run and sign = booked)

Per variant:
  1. write the GAID into GMS adid_settings.xml (root) — the app must PRESENT the
     same id the click carries, else nothing can join
  2. fire the click (macros expanded: click_id=<adid>, sub3=<adid>) with a
     MARKER creative so a join is unmistakable
  3. wipe the app's Adjust state + relaunch  -> genuine, booked install
  4. read /data/data/com.penti.app/files/AdjustAttribution (the server's answer)
     + the app's installReferrer from AdjustIoActivityState

Variants:
  A  GAID = <device data adid>   -> "does my existing device data/click win?"
                                    (also reveals whether the earlier install
                                     with this id already booked an attribution)
  B  GAID = fresh uuid4          -> control; proves the pipeline end to end

Usage:
  python farm_win.py --device-json <file|json> [--link <url>] [--adid <uuid>]
                     [--referrer <string>] [--creative cline_fw]
"""
import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import click_bind_chain as cb

PKG = "/data/data/com.penti.app"
STATE = PKG + "/files/AdjustIoActivityState"
ATTR = PKG + "/files/AdjustAttribution"
XML = "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml"
GMS = "com.google.android.gms"
APP = "com.penti.app"
UUID_RE = rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
OUT = os.path.join(HERE, "farm_win_result.json")


def sh(cmd, serial=None):
    a = ["adb"] + (["-s", serial] if serial else []) + ["shell", cmd]
    r = subprocess.run(a, capture_output=True)
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def su(cmd, serial=None):
    b = base64.b64encode(cmd.encode()).decode()
    inner = "echo %s | base64 -d | sh" % b
    b2 = base64.b64encode(inner.encode()).decode()
    return sh('/debug_ramdisk/su -c "echo %s | base64 -d | sh"' % b2, serial)


def su_file(path, serial=None):
    a = ["adb"] + (["-s", serial] if serial else []) + \
        ["shell", '/debug_ramdisk/su -c "cat %s | base64"' % path]
    r = subprocess.run(a, capture_output=True)
    try:
        return base64.b64decode(r.stdout)
    except Exception:
        return b""


def get_gaid(serial=None):
    m = re.search(rb'name="adid_key">([^<]*)<',
                  su_file(XML, serial).replace(b"\r", b""))
    return m.group(1).decode() if m else None


def set_gaid(new, serial=None):
    cur = su_file(XML, serial).replace(b"\r", b"")
    old = re.search(UUID_RE, cur)
    if not old:
        return None
    o = old.group(0).decode()
    su("cp %s /data/local/tmp/adid_%s.bak" % (XML, o), serial)
    patch = cur.replace(old.group(0), new.encode())
    su("echo %s | base64 -d > /data/local/tmp/adid_new.xml"
       % base64.b64encode(patch).decode(), serial)
    su("cat /data/local/tmp/adid_new.xml > %s" % XML, serial)
    su("am force-stop %s" % GMS, serial)
    time.sleep(2)
    return get_gaid(serial)


def json_of(blob):
    m = re.search(r"\{[^{}]*tracker_token[^{}]*\}", blob)
    return json.loads(m.group(0)) if m else {}


def read_verdict(serial=None):
    at = su_file(ATTR, serial).decode("ascii", "replace")
    st = su_file(STATE, serial).decode("ascii", "replace")
    ref = re.search(r"utm_source[^\x00]{0,120}", st)
    return json_of(at), (ref.group(0) if ref else "")


def wipe_relaunch(serial=None):
    su("rm -f %s %s" % (STATE, ATTR), serial)
    su("am force-stop %s" % APP, serial)
    time.sleep(2)
    su("am start -n %s/.ui.main.MainActivity" % APP, serial)


def fire_click(gps, creative, link, use_idfa=True, use_gps=True,
               serial=None):
    if link:
        url = link
    else:
        url = cb.LINK
    url = url.replace("creative=penti_generic", "creative=" + creative)
    url = cb.expand(url, gps)
    parts = urllib.parse.urlsplit(url)
    q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    if use_idfa:
        q["idfa"] = gps
    if use_gps:
        q["gps_adid"] = gps
    url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                   urllib.parse.urlencode(q), ""))
    code, ref, hops = cb.tracker_click(url, gps)
    return code, ref, hops, url


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--device-json", default=None,
                    help="clicker device data (file path or raw JSON)")
    ap.add_argument("--link", default=None, help="clicked link (or template)")
    ap.add_argument("--adid", default=None, help="override the device-data adid")
    ap.add_argument("--referrer", default=None,
                    help="already-clicked referrer (informational/verification)")
    ap.add_argument("--creative", default="cline_fw")
    ap.add_argument("--no-click", action="store_true",
                    help="do NOT fire a click: verify an ALREADY-fired click "
                         "(use with a fresh device-data adid)")
    ap.add_argument("--gaid", default=None,
                    help="run ONLY this variant: set GAID, fire fresh click, read verdict")
    ap.add_argument("--serial", default=None)
    args = ap.parse_args()

    dev_adid = args.adid
    dev = {}
    if args.device_json:
        raw = args.device_json
        if os.path.exists(raw):
            raw = open(raw, encoding="utf-8", errors="replace").read()
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            dev = json.loads(m.group(0))
            dev_adid = (dev_adid or dev.get("adid") or dev.get("device_id")
                        or dev.get("android_id"))
    serial = args.serial
    print("serial=%s device-data adid=%s model=%s"
          % (serial, dev_adid, dev.get("model")), flush=True)
    print("current GAID: %s" % get_gaid(serial), flush=True)

    res = {"device_adid": dev_adid, "device_model": dev.get("model"),
           "runs": []}
    variants = []
    if args.gaid:
        variants.append(("G gaid-flag", args.gaid, True))
    else:
        if dev_adid:
            variants.append(("A existing device-data id", dev_adid, True))
        variants.append(("B fresh id (control)", str(uuid.uuid4()), True))

    for label, gps, _ in variants:
        got = set_gaid(gps, serial)
        print("\n=== %s\n    GAID -> %s (readback %s)" % (label, gps, got),
              flush=True)
        creative = args.creative + ("_a" if "device-data" in label else "_b")
        if args.no_click:
            code, ref = -1, args.referrer or "(no click fired)"
            print("    click SKIPPED (--no-click): verifying the already-fired "
                  "click", flush=True)
        else:
            code, ref, hops, url = fire_click(gps, creative, args.link,
                                              serial=serial)
            print("    click %s reftag=%s"
                  % (code, (ref or "").split("&")[0]), flush=True)
        wipe_relaunch(serial)
        a, app_ref = {}, ""
        for k in range(5):
            time.sleep(12 if k == 0 else 10)
            a, app_ref = read_verdict(serial)
            if a:
                break
        print("    app installReferrer: %s" % app_ref[:120], flush=True)
        print("    server verdict: token=%s network=%s creative=%s eng=%s "
              "inst=%s" % (a.get("tracker_token"), a.get("network"),
                           a.get("creative"), a.get("engagement_time"),
                           a.get("installed_at")), flush=True)
        ok = bool(a) and a.get("network") not in (None, "Organic") \
            and a.get("creative") == creative
        print("    -> %s" % ("NON-ORGANIC (marker joined!)" if ok else
                             ("Organic" if a.get("network") == "Organic"
                              else "other: %s" % a.get("network"))),
              flush=True)
        res["runs"].append({"label": label, "gaid": gps, "gaid_readback": got,
                            "creative": creative, "click_http": code,
                            "referrer": ref, "verdict": a,
                            "app_install_referrer": app_ref,
                            "non_organic_marker_joined": ok})
        time.sleep(4)
    json.dump(res, open(OUT, "w"), indent=1)
    print("\nsaved", OUT, flush=True)


if __name__ == "__main__":
    main()