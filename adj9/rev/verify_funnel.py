"""verify_funnel.py — THE unexecuted last step of the funnel campaign.

Python books the install (real click -> crafted-signed session -> sdk_click,
NO crafted attribution polls), then the app on the moto g42 reads the TRUE
verdict from its own AdjustAttribution file.

If tracker != Organic here, a crafted-signed Python session BOOKED non-organic
(device used only as the reader) — goal achieved. If Organic, this is the first
SOUND negative for "python-created install" (all prior crafted-poll Organic
results were fallback-blind, slices 90/91/97/110/143).
"""
import base64
import json
import os
import re
import socket
import subprocess
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as F
import run_funnel as RF

SERIAL = "ZD2228MY3X"
PKG = "com.penti.app"
OUT = os.path.join(HERE, "verify_funnel_result.json")


def adb(*a, t=60):
    r = subprocess.run(["adb", "-s", SERIAL] + list(a), capture_output=True, timeout=t)
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def su(cmd):
    b = base64.b64encode(cmd.encode()).decode()
    inner = "echo %s | base64 -d | sh" % b
    b2 = base64.b64encode(inner.encode()).decode()
    return adb("shell", '/debug_ramdisk/su -c "echo %s | base64 -d | sh"' % b2)


def set_gaid(new):
    XML = "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml"
    cur = su("cat %s" % XML)
    m = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", cur)
    if not m:
        return None
    old = m.group(0)
    patched = cur.replace(old, new)
    b64 = base64.b64encode(patched.encode()).decode()
    su("echo %s | base64 -d > /data/local/tmp/adid_new.xml && "
       "cat /data/local/tmp/adid_new.xml > %s" % (b64, XML))
    su("am force-stop com.google.android.gms")
    return old


def fiddler_up():
    try:
        s = socket.create_connection(("127.0.0.1", 8888), timeout=1)
        s.close()
        return True
    except Exception:
        return False


def main():
    res = {}
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    print("[funnel] fresh gps=%s auid=%s" % (gps, auid), flush=True)

    # link: replace every occurrence of yesterday's GAID with the fresh one
    old = "80970d76-1b90-4e28-97cc-a6e5cd55f690"
    link = RF.LINK.replace(old, gps)
    assert gps in link and old not in link

    dev = json.loads(RF.DEVICE_JSON)
    F.DEV, F.UA = RF.dev_from_json(dev), RF.ua_from_json(dev)
    F.OFF_MINUTES, F.OFF_LABEL = 330, "+0530"
    F.ADD_IDFA = False
    if fiddler_up():
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:8888"
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8888"
        F.USE_PROXY = True
        print("[funnel] proxy ON (Fiddler detected)", flush=True)
    else:
        F.USE_PROXY = False
        print("[funnel] direct (no Fiddler on 8888)", flush=True)

    # STEP 1 — real click, fresh GAID stamped
    t_click = time.time()
    ref, hop = RF.click_tracker(link, gps, F.UA, dev)
    print("[funnel] REFERRER:", (ref or "")[:120], flush=True)
    assert ref and "adjust_reftag=" in ref, "tracker gave no referrer"
    res["referrer"] = ref
    res["reftag"] = ref.split("adjust_reftag=", 1)[1].split("&")[0]

    tb = int(t_click) + 30
    ins = F.fmt(int(t_click) + 37, 774)
    print("[funnel] first-open delay 25s (CTIT ~62s)...", flush=True)
    time.sleep(25)

    # STEP 2 — crafted-signed session (creates the install record)
    s2, r2 = F.api_session(gps, auid, ins)
    print("[funnel] SESSION:", s2, r2[:200], flush=True)
    res["session"] = [s2, r2[:300]]
    time.sleep(3)

    # STEP 3 — sdk_click with the real referrer
    s1, r1 = F.api_sdk_click(gps, auid, ref, int(t_click), tb, ins)
    print("[funnel] SDK_CLICK:", s1, r1[:200], flush=True)
    res["sdk_click"] = [s1, r1[:300]]
    # STEP 4 — intentionally ABSENT: no crafted attribution polls, ever.

    res.update(gps=gps, auid=auid)
    json.dump(res, open(OUT, "w"), indent=1)

    # ---------- device read (moto g42) ----------
    print("[device] backing up current AdjustAttribution...", flush=True)
    prev = su("cat /data/data/%s/files/AdjustAttribution 2>/dev/null" % PKG)
    open(os.path.join(HERE, "verify_prev_attribution.bak"), "w").write(prev)
    print("[device] prev (first 160):", prev[:160].replace("\n", " "), flush=True)

    old_gaid = set_gaid(gps)
    print("[device] GAID: %s -> %s" % (old_gaid, gps), flush=True)
    res["old_gaid"] = old_gaid
    time.sleep(2)

    su("am force-stop %s" % PKG)
    su("rm -rf /data/data/%s/files /data/data/%s/shared_prefs "
       "/data/data/%s/databases" % (PKG, PKG, PKG))
    time.sleep(1)
    adb("shell", "am start -n %s/.ui.main.MainActivity" % PKG)
    print("[device] app launched; polling for its own attribution read...",
          flush=True)

    verdict = None
    for i in range(10):
        time.sleep(12)
        raw = su("cat /data/data/%s/files/AdjustAttribution 2>/dev/null" % PKG)
        m = re.search(r'\{"tracker_token.*?\}', raw)
        if m:
            try:
                verdict = json.loads(m.group(0) + "}")
            except Exception:
                pass
            if verdict:
                break
    print(flush=True)
    if verdict:
        print("VERDICT: token=%s network=%s" % (verdict.get("tracker_token"),
                                                verdict.get("network")))
        print("  tracker_name=%s creative=%s" % (verdict.get("tracker_name"),
                                                 verdict.get("creative")))
        print("  eng=%s inst=%s reattr=%s" % (verdict.get("engagement_time"),
                                              verdict.get("installed_at"),
                                              verdict.get("is_reattributed")))
    else:
        print("VERDICT: none yet (app file empty after 120s)")
    res["verdict_device_oracle"] = verdict
    json.dump(res, open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()
