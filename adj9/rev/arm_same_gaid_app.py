"""arm_same_gaid_app.py — THE CONTROL that closes arm_transport2.

arm_transport2 fired a device click on a fresh GMS-backed GAID and then had
PYTHON send /session + /sdk_click (device egress, g42 profile, real CTIT,
corrected F.py region). Result: Organic.

That leaves exactly two explanations, and this script separates them by
holding the GAID and the click FIXED and changing only the sender:

  A) The click record was never qualifying.
     -> the APP, on this same GAID + this same click, will read Organic.
  B) The click record WAS qualifying, and the app's own transmission is what
     books it.
     -> the APP, on this same GAID + this same click, will read NON-ORGANIC.

We do NOT clear the GAID. We only wipe the app's own state (files/prefs/db)
so it performs a genuine first_open, then read its AdjustAttribution file.

Case B is the decisive proof that our signature is sufficient and the
remaining difference is app provenance / install lifecycle, not the blob.
"""
import base64
import json
import os
import re
import subprocess
import sys
import time

SERIAL = "ZD2228MY3X"
PKG = "com.penti.app"
HERE = os.path.dirname(os.path.abspath(__file__))
PRIOR = os.path.join(HERE, "arm_transport2_result.json")
OUT = os.path.join(HERE, "arm_same_gaid_app_result.json")

# GAID + adid from the Python run we are controlling against.
prior = json.load(open(PRIOR))
GAID = prior["gps"]
ADID = prior["session"][1]
ADID = json.loads(ADID)["adid"] if isinstance(ADID, str) else ADID["adid"]


def su(cmd):
    b = base64.b64encode(cmd.encode()).decode()
    inner = "echo %s | base64 -d | sh" % b
    b2 = base64.b64encode(inner.encode()).decode()
    r = subprocess.run(["adb", "-s", SERIAL, "shell",
                        '/debug_ramdisk/su -c "echo %s | base64 -d | sh"' % b2],
                       capture_output=True, timeout=90)
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def read_attribution():
    """The file is Java-serialized with the JSON embedded, not JSON-prefixed.

    The match must be GREEDY: the serialization envelope contains braces of
    its own, so a non-greedy `.*?}` stops at the wrong place and yields no
    parse even though the attribution is present.
    """
    raw = su("cat /data/data/%s/files/AdjustAttribution 2>/dev/null" % PKG)
    raw = raw.replace("\x00", "")
    m = re.search(r'\{"tracker_token.*\}', raw)
    if not m:
        return None, raw[:400]
    try:
        return json.loads(m.group(0)), raw[:400]
    except Exception:
        return None, m.group(0)[:400]


def main():
    res = {"control": "same GAID + same click, APP sends the session",
           "gps": GAID, "python_adid": ADID}

    # Confirm the GAID is still the one in Play services.
    cur = su("cat /data/data/com.google.android.gms/shared_prefs/adid_settings.xml")
    m = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", cur)
    live = m.group(0) if m else None
    res["live_gaid_before"] = live
    print("GAID in GMS : %s" % live)
    print("GAID used   : %s" % GAID)
    if live != GAID:
        print("!! GMS GAID drifted; re-installing the target GAID")
        xml = "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml"
        b64 = base64.b64encode(cur.replace(live, GAID).encode()).decode()
        su("echo %s | base64 -d > /data/local/tmp/adid3.xml && "
           "cat /data/local/tmp/adid3.xml > %s" % (b64, xml))
        su("am force-stop com.google.android.gms")
        time.sleep(2)

    # Wipe ONLY the app's own state -> genuine first_open. GAID untouched.
    su("am force-stop %s" % PKG)
    su("rm -rf /data/data/%s/files /data/data/%s/shared_prefs "
       "/data/data/%s/databases" % (PKG, PKG, PKG))
    time.sleep(1)
    print("launching app for genuine first_open...", flush=True)
    subprocess.run(["adb", "-s", SERIAL, "shell",
                    "am start -n %s/.ui.main.MainActivity" % PKG],
                   capture_output=True, timeout=60)

    verdict = None
    for i in range(10):
        time.sleep(12)
        verdict, raw = read_attribution()
        if verdict:
            break
        print("  waiting %d/10..." % (i + 1), flush=True)

    print()
    if not verdict:
        print("!! no AdjustAttribution written")
        res["verdict"] = None
        res["raw"] = raw
    else:
        print("APP VERDICT (same GAID + same click, app sent the session)")
        print("  tracker_token : %s" % verdict.get("tracker_token"))
        print("  network       : %s" % verdict.get("network"))
        print("  tracker_name  : %s" % verdict.get("tracker_name"))
        print("  engagement    : %s" % verdict.get("engagement_time"))
        print("  installed_at  : %s" % verdict.get("installed_at"))
        v_adid = verdict.get("adid") or verdict.get("adjust_id")
        print("  adid          : %s" % v_adid)
        print("  python adid   : %s" % ADID)
        res["verdict"] = verdict
        res["app_adid"] = v_adid
        res["SAME_ADID"] = bool(v_adid and v_adid == ADID)
        eng = verdict.get("engagement_time") or ""
        res["JOINED"] = bool(eng) and not eng.startswith("0001-01-01")
        print()
        if res["JOINED"]:
            print("=> NON-ORGANIC on the SAME click Python could not book.")
            print("   => the click WAS qualifying. Case B: the app's own")
            print("      transmission is the gate, not our signature.")
        else:
            print("=> ORGANIC on the same click. Case A: this click record")
            print("   was never qualifying for anyone.")

    json.dump(res, open(OUT, "w"), indent=1)
    print("\nsaved", OUT)


if __name__ == "__main__":
    main()
