r"""win_attempt.py — the end-to-end "can Python win a non-organic install" test.

Per variant:
  1. write a FRESH GAID into GMS adid_settings.xml (+ restart GMS)  [new identity]
  2. PYTHON fires the tracker click bound to that GAID (idfa/click_id/callbacks),
     with a MARKER creative so a joined attribution is unmistakable
  3. wipe the app's Adjust state + relaunch -> the SDK does a fresh install and
     asks attribution with a genuine (booked) signature
  4. read the device's own AdjustAttribution

Readings:
  * non-organic + OUR creative + engagement ~= now  -> WON: a Python click earned
    a non-organic install (the whole pipeline works)
  * Organic                                        -> our click is not attributable
  * old 24pxw9rl / installed 2026-09-14T12:23:08Z  -> the GAID change did not take
    (variant invalid, identity unchanged)

Click styles: both(idfa+gps_adid) / idfa only / gps_adid only — the clicker uses
idfa, slice 87 tried both; each gets its own fresh GAID and creative marker.

Usage: python win_attempt.py [n_variants]
"""
import base64
import json
import os
import re
import subprocess
import sys
import time
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
OUT = os.path.join(HERE, "win_attempt_result.json")

STYLES = [("both", True, True), ("idfa", True, False), ("gps", False, True)]
MARKERS = ["cline_w1", "cline_w2", "cline_w3"]


def sh(cmd):
    r = subprocess.run(["adb", "shell", cmd], capture_output=True)
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def su(cmd):
    b = base64.b64encode(cmd.encode()).decode()
    inner = "echo %s | base64 -d | sh" % b
    b2 = base64.b64encode(inner.encode()).decode()
    return sh('/debug_ramdisk/su -c "echo %s | base64 -d | sh"' % b2)


def su_file(path):
    r = subprocess.run(["adb", "shell",
                        '/debug_ramdisk/su -c "cat %s | base64"' % path],
                       capture_output=True)
    try:
        return base64.b64decode(r.stdout)
    except Exception:
        return b""


def current_gaid():
    m = re.search(rb'name="adid_key">([^<]*)<', su_file(XML).replace(b"\r", b""))
    return m.group(1).decode() if m else None


def set_gaid(new):
    cur = su_file(XML).replace(b"\r", b"")
    old = re.search(UUID_RE, cur)
    if not old:
        return None
    patch = cur.replace(old.group(0), new.encode())
    b64 = base64.b64encode(patch).decode()
    su("cp %s /data/local/tmp/adid_%s.bak" % (XML, old.group(0).decode()))
    su("echo %s | base64 -d > /data/local/tmp/adid_new.xml" % b64)
    su("cat /data/local/tmp/adid_new.xml > %s" % XML)
    su("am force-stop %s" % GMS)
    time.sleep(2)
    return current_gaid()


def read_attr():
    at = su_file(ATTR)
    txt = at.decode("ascii", "replace")
    m = re.search(r'\{"tracker_token".{0,500}', txt)
    return m.group(0) if m else ""


def wipe_relaunch():
    su("rm -f %s %s" % (STATE, ATTR))
    su("am force-stop %s" % APP)
    time.sleep(2)
    su("am start -n %s/.ui.main.MainActivity" % APP)


def click(gps, creative, use_idfa, use_gps):
    link = cb.LINK.replace("creative=penti_generic", "creative=" + creative)
    url = cb.expand(link, gps)
    import urllib.parse
    parts = urllib.parse.urlsplit(url)
    q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    if not use_idfa:
        q.pop("idfa", None)
    if not use_gps:
        q.pop("gps_adid", None)
    url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                   urllib.parse.urlencode(q), ""))
    code, ref, hops = cb.tracker_click(url, gps)
    return code, ref, hops


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    res = {"start_gaid": current_gaid(), "runs": []}
    print("start GAID: %s" % res["start_gaid"], flush=True)
    for i in range(min(n, len(STYLES))):
        name, use_idfa, use_gps = STYLES[i]
        marker = MARKERS[i]
        new = str(uuid.uuid4())
        got = set_gaid(new)
        print("\n=== variant %d (%s) marker=%s\n    GAID -> %s (readback %s)"
              % (i + 1, name, marker, new, got), flush=True)
        code, ref, hops = click(new, marker, use_idfa, use_gps)
        print("    click http=%s %s" % (code, (ref or "").split("&")[0]),
              flush=True)
        t_click = int(time.time())
        wipe_relaunch()
        att = ""
        for k in range(5):
            time.sleep(12 if k == 0 else 10)
            att = read_attr()
            if att:
                break
        joined = ("cline_w" in att)
        print("    attribution: %s" % att[:400], flush=True)
        print("    -> %s" % ("OUR CLICK JOINED!" if joined else
                             ("Organic" if "wy7261z" in att else "other/old")),
              flush=True)
        res["runs"].append({"variant": i + 1, "style": name, "marker": marker,
                            "gaid_set": new, "gaid_readback": got,
                            "click_http": code, "referrer": ref,
                            "t_click": t_click, "attribution": att,
                            "our_click_joined": joined})
        time.sleep(4)
    json.dump(res, open(OUT, "w"), indent=1)
    print("\nsaved", OUT, flush=True)


if __name__ == "__main__":
    main()