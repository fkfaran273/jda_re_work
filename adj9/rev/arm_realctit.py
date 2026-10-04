"""arm_realctit.py — the CORRECTED transport arm, at the device's REAL CTIT.

arm_transport2.py was invalid: it waited 217s between click and install,
copying CTIT from arm_c_corrected (a PC experiment built on a different SAZ
capture). The actual g42 device win is:

    engagement_time 2026-09-24T09:07:49Z
    installed_at    2026-09-24T09:07:55Z      -> CTIT = 6 SECONDS

and the re-run today gave 5 seconds (10:15:02 -> 10:15:07). The real app is
launched ~1s after the click and its first session lands within seconds. So
transport2 tested a delay the winning device never used, and its "Organic"
proves nothing about the real path.

This arm runs the SAME single-variable experiment (Python sends the install
instead of the app) at the device's true timing, and sweeps several CTITs so
we can see whether click-to-install delay is itself a discriminator.

Everything else is held to the winning recipe:
  fresh GAID written into GMS, click fired FROM THE DEVICE, moto g42 /
  Android 12 profile with no mcc/mnc, corrected F.py region, device egress,
  Play install referrer, app NEVER launched before the verdict.

The app control (fresh_click_install_g42.py) is the known-good reference and
is re-run by the caller for comparison.
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

import mint_pipeline as M
import adj9_full_chain as FC

SERIAL = "ZD2228MY3X"
PROFILE = json.load(open(os.path.join(HERE, "moto_g42_profile.json")))
OUT = os.path.join(HERE, "arm_realctit_result.json")

FC.DEV = dict(PROFILE["DEV"])
FC.UA = PROFILE["UA"]
FC.OFF_MINUTES, FC.OFF_LABEL = PROFILE["OFF_MINUTES"], PROFILE["OFF_LABEL"]
FC.ADD_IDFA = PROFILE["ADD_IDFA"]
FC.USE_PROXY = False
FC.USE_DEVICE = True

CLICK_URL = ("https://app.adjust.com/1sd1lk6a?campaign=AH"
             "&adgroup=vkm_0926_36&creative=cline_1p8t3"
             "&click_id=%s&idfa=%s&gps_adid=%s")
CLICK_UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36")
PLAY_REFERRER = "utm_source=(not%20set)&utm_medium=(not%20set)"

# The device's true click->install delay, plus a couple of probes either side.
CTITS = [6.0, 30.0, 120.0]


def su(cmd):
    b = base64.b64encode(cmd.encode()).decode()
    inner = "echo %s | base64 -d | sh" % b
    b2 = base64.b64encode(inner.encode()).decode()
    r = subprocess.run(["adb", "-s", SERIAL, "shell",
                        '/debug_ramdisk/su -c "echo %s | base64 -d | sh"' % b2],
                       capture_output=True, timeout=90)
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def set_gaid(new):
    xml = "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml"
    cur = su("cat %s" % xml)
    m = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", cur)
    if not m:
        return None
    old = m.group(0)
    b64 = base64.b64encode(cur.replace(old, new).encode()).decode()
    su("echo %s | base64 -d > /data/local/tmp/adid4.xml && "
       "cat /data/local/tmp/adid4.xml > %s" % (b64, xml))
    su("am force-stop com.google.android.gms")
    return old


def one_run(ctit):
    fresh = str(uuid.uuid4())
    old = set_gaid(fresh)
    print("\n" + "=" * 62)
    print(" CTIT %.0fs   GAID %s (was %s)" % (ctit, fresh, old), flush=True)
    print("=" * 62, flush=True)
    time.sleep(2)

    # click FROM THE DEVICE, exactly like the winning script
    url = CLICK_URL % (fresh, fresh, fresh)
    r = su("curl -s -o /dev/null -w '%%{http_code}' -L '%s' "
           "-H 'User-Agent: %s'" % (url, CLICK_UA))
    print(" click from device: HTTP %s" % r.strip()[-3:], flush=True)
    t_click = time.time()

    # WAIT THE REAL CTIT — this is the variable under test
    w = ctit - (time.time() - t_click)
    if w > 0:
        print(" waiting %.0fs..." % w, flush=True)
        time.sleep(w)

    auid = str(uuid.uuid4())
    ins = FC.fmt(int(t_click) + int(ctit), int((ctit % 1) * 1000))
    tb = t_click + max(ctit - 3.0, 0.5)

    print(" /session (python mint, device egress)...", flush=True)
    s2, r2 = M.api_session_mint(fresh, auid, ins)
    r2 = r2.decode("utf-8", "replace") if isinstance(r2, bytes) else r2
    print("   -> %s %s" % (s2, r2[:140]), flush=True)
    time.sleep(3)

    print(" /sdk_click...", flush=True)
    s1, r1 = M.api_sdk_click_mint(fresh, auid, PLAY_REFERRER,
                                  int(t_click), tb, ins)
    r1 = r1.decode("utf-8", "replace") if isinstance(r1, bytes) else r1
    print("   -> %s %s" % (s1, r1[:140]), flush=True)

    time.sleep(5)
    joined = False
    best = None
    for i in range(5):
        st, body = M.api_attribution_mint(fresh, auid, "pt-" + auid[:8], "sdk")
        body = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
        try:
            a = json.loads(body).get("attribution", {})
        except Exception:
            a = {}
        eng = a.get("engagement_time")
        j = bool(eng) and not eng.startswith("0001-01-01")
        print("   poll %d/5 %s token=%s network=%s eng=%s => %s"
              % (i + 1, st, a.get("tracker_token"), a.get("network"), eng,
                 "JOINED" if j else "organic"), flush=True)
        if j:
            joined = True
            best = a
            break
        if i == 4:
            best = a
        time.sleep(20)

    return {"ctit": ctit, "gps": fresh, "auid": auid,
            "session": [s2, r2[:300]], "sdk_click": [s1, r1[:300]],
            "verdict": best, "JOINED": joined}


def main():
    res = {"arm": "real-CTIT transport (python mint, device egress)",
           "note": "arm_transport2 used a bogus 217s CTIT; the real g42 win "
                   "is ~5-6s click->install. This sweeps the true timing.",
           "runs": []}
    for ctit in CTITS:
        try:
            res["runs"].append(one_run(ctit))
        except Exception as e:
            print("  !! run failed: %s" % e, flush=True)
            res["runs"].append({"ctit": ctit, "error": str(e)[:200]})
        json.dump(res, open(OUT, "w"), indent=1)

    print("\n" + "=" * 62)
    print(" SUMMARY")
    print("=" * 62)
    for r in res["runs"]:
        if "error" in r:
            print("  CTIT %5.0fs  ERROR %s" % (r["ctit"], r["error"]))
        else:
            v = r.get("verdict") or {}
            print("  CTIT %5.0fs  %-10s token=%-9s network=%s"
                  % (r["ctit"], "JOINED" if r["JOINED"] else "organic",
                     v.get("tracker_token"), v.get("network")))
    print("\n Any JOINED => the signature IS sufficient and CTIT/timing was "
          "the gate.\n All organic => the app-transmission difference is real.")
    print("saved", OUT)


if __name__ == "__main__":
    main()
