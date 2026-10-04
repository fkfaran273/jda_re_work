"""arm_transport2.py — the DECISIVE transport/provenance isolation.

This is the winning g42 device path (G42_WIN_RESULT.md) with exactly ONE
variable changed: instead of the APP sending its own first session, PYTHON
sends the session + sdk_click, using the real mint (F.py region, FinEx VM).

Held IDENTICAL to the win:
  * fresh GAID, set into Google Play services on the device itself
  * the click fired FROM THE DEVICE (same egress IP, same Chrome UA)
  * moto g42 / Android 12 profile, no mcc/mnc
  * real CTIT: click -> install_begin 210s, click -> installed_at 217.431s
  * Play install referrer on /sdk_click
  * all four calls transported by the DEVICE (adb shell curl)

The ONLY delta vs the win is who signs and sends the install:
  win  = the app's own code
  here = our Python mint

So a JOIN here proves the signature+mint is sufficient and the gate was
transport/app-provenance. Organic here proves the opposite: even a
byte-faithful, device-egress, device-click, device-profile install does not
join without the app itself sending it.

Verdict oracle = attribution response engagement_time (nonzero = joined).
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
import run_funnel as RF
import adj9_full_chain as FC

SERIAL = "ZD2228MY3X"
PROFILE = json.load(open(os.path.join(HERE, "moto_g42_profile.json")))
CTIT_INSTALL = 217.431
CTIT_BEGIN = 210.0
OUT = os.path.join(HERE, "arm_transport2_result.json")

FC.DEV = dict(PROFILE["DEV"])
FC.UA = PROFILE["UA"]
FC.OFF_MINUTES, FC.OFF_LABEL = PROFILE["OFF_MINUTES"], PROFILE["OFF_LABEL"]
FC.ADD_IDFA = PROFILE["ADD_IDFA"]
FC.USE_PROXY = False
FC.USE_DEVICE = True          # <-- transport by the phone (device egress + TLS)

CLICK_URL = ("https://app.adjust.com/1sd1lk6a?campaign=AH"
             "&adgroup=vkm_0926_36&creative=cline_1p8t3"
             "&click_id=%s&idfa=%s&gps_adid=%s")
CLICK_UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36")
# Real Google Play install referrer, exactly as the winning device signed it in
# its /sdk_click d10 (device/win_capture_rows.json row 1, 387 B). A "(not set)"
# placeholder makes the click d10 4 B longer and the click does not bind to the
# campaign, so the install falls back to Organic.
PLAY_REFERRER = "utm_source=google-play&utm_medium=organic"


def su(cmd):
    """Run a shell command as root on the device."""
    b = base64.b64encode(cmd.encode()).decode()
    inner = "echo %s | base64 -d | sh" % b
    b2 = base64.b64encode(inner.encode()).decode()
    r = subprocess.run(["adb", "-s", SERIAL, "shell",
                        '/debug_ramdisk/su -c "echo %s | base64 -d | sh"' % b2],
                       capture_output=True, timeout=90)
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def set_gaid(new):
    """Install a fresh GAID into Google Play services, as the win script did."""
    xml = "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml"
    cur = su("cat %s" % xml)
    m = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", cur)
    if not m:
        print("!! could not read current GAID", flush=True)
        return None
    old = m.group(0)
    b64 = base64.b64encode(cur.replace(old, new).encode()).decode()
    su("echo %s | base64 -d > /data/local/tmp/adid2.xml && "
       "cat /data/local/tmp/adid2.xml > %s" % (b64, xml))
    su("am force-stop com.google.android.gms")
    return old


def main():
    res = {"arm": "transport2 (device click + device egress + PYTHON mint)"}
    fresh = str(uuid.uuid4())
    old = set_gaid(fresh)
    print("GAID: %s -> %s" % (old, fresh), flush=True)
    time.sleep(2)
    res["gps"] = fresh

    # STEP 1 — click FROM THE DEVICE (identical egress to the winning run).
    # Record click_time at click INITIATION (before the request round-trips),
    # matching the genuine app, rather than after the 302 returns.
    t_click = time.time()
    url = CLICK_URL % (fresh, fresh, fresh)
    r = su("curl -s -o /dev/null -w '%%{http_code}' -L '%s' "
           "-H 'User-Agent: %s'" % (url, CLICK_UA))
    print("STEP 1/4 click from device: HTTP %s" % r.strip()[-3:], flush=True)
    res["click"] = r.strip()[-3:]

    # STEP 2 — wait the real CTIT before the install session.
    wait = CTIT_INSTALL - (time.time() - t_click)
    print("STEP 2/4 waiting %.0fs for CTIT..." % max(wait, 0), flush=True)
    if wait > 0:
        time.sleep(wait)

    # STEP 3 — PYTHON-minted session, transported by the device.
    auid = str(uuid.uuid4())
    ins = FC.fmt(int(t_click) + int(CTIT_INSTALL), 431)
    tb = t_click + CTIT_BEGIN
    print("STEP 3/4 /session (python mint, device transport)...", flush=True)
    s2, r2 = M.api_session_mint(fresh, auid, ins)
    r2 = r2.decode("utf-8", "replace") if isinstance(r2, bytes) else r2
    print("  -> %s %s" % (s2, r2[:200]), flush=True)
    res["session"] = [s2, r2[:400]]
    res["auid"] = auid
    json.dump(res, open(OUT, "w"), indent=1)
    # Genuine app fires sdk_click ~93ms after session; do not add an artificial gap.
    time.sleep(0.1)

    print("STEP 4/4 /sdk_click (python mint, device transport)...", flush=True)
    s1, r1 = M.api_sdk_click_mint(fresh, auid, PLAY_REFERRER,
                                 int(t_click), tb, ins)
    r1 = r1.decode("utf-8", "replace") if isinstance(r1, bytes) else r1
    print("  -> %s %s" % (s1, r1[:200]), flush=True)
    res["sdk_click"] = [s1, r1[:600]]
    json.dump(res, open(OUT, "w"), indent=1)

    # VERDICT — poll attribution from the device too.
    time.sleep(5)
    verdicts = []
    for i in range(4):
        st, body = M.api_attribution_mint(fresh, auid, "pt-" + auid[:8], "backend")
        body = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
        try:
            a = json.loads(body).get("attribution", {})
        except Exception:
            a = {}
        eng = a.get("engagement_time")
        joined = bool(eng) and not eng.startswith("0001-01-01")
        print("  poll %d/4 %s token=%s network=%s eng=%s => %s"
              % (i + 1, st, a.get("tracker_token"), a.get("network"), eng,
                 "JOINED" if joined else "organic"), flush=True)
        verdicts.append({"status": st, "token": a.get("tracker_token"),
                         "network": a.get("network"),
                         "engagement_time": eng, "joined": joined,
                         "installed_at": a.get("installed_at")})
        if joined or i == 3:
            break
        time.sleep(25)

    res["verdicts"] = verdicts
    res["JOINED"] = any(v["joined"] for v in verdicts)
    json.dump(res, open(OUT, "w"), indent=1)
    print("\n" + "=" * 60)
    print(" VERDICT: %s" % ("NON-ORGANIC — python mint DID join"
                            if res["JOINED"] else "Organic"))
    print("=" * 60)
    print("saved", OUT)


if __name__ == "__main__":
    main()
