"""verify_funnel2.py — isolate the signer: EXACTLY the winning device path
(fresh GAID -> click fired FROM THE DEVICE -> wipe -> launch -> app reads
verdict) with ONE change: before the app launches, our crafted-signed Python
session books the install on that GAID.

Win path (fresh_click_install.py, 11/11): device click + app session -> VKM.
This run: device click + CRAFTED PC session -> app session is #2, only reads.
If Organic => the booking session's signer is the discriminator (wall holds at
booking). If VKM => Python booking works with a device-side click.
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
import adj9_full_chain as F
import run_funnel as RF

SERIAL = "ZD2228MY3X"
PKG = "com.penti.app"
OUT = os.path.join(HERE, "verify_funnel2_result.json")


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


def main():
    res = {}
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    print("[v2] fresh gps=%s" % gps, flush=True)

    # 1) GAID on device FIRST (click must carry it)
    old_gaid = set_gaid(gps)
    print("[v2] GAID: %s -> %s" % (old_gaid, gps), flush=True)
    res["old_gaid"] = old_gaid
    time.sleep(2)

    # 2) click FROM THE DEVICE (win-path shape, moto g42 UA)
    url = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
           "&creative=penti_generic&click_id=%s&idfa=%s&gps_adid=%s"
           % (gps, gps, gps))
    r = adb("shell", "curl -s -o /dev/null -w '%%{http_code}' -L '%s' "
                   "-H 'User-Agent: Mozilla/5.0 (Linux; Android 12; moto g 42)'"
            % url, t=90)
    print("[v2] device click http:", r.strip()[-3:], flush=True)
    res["device_click"] = r.strip()[-3:]
    t_click = time.time()

    # 3) crafted-signed session books the install from the PC
    dev = json.loads(RF.DEVICE_JSON)
    F.DEV, F.UA = RF.dev_from_json(dev), RF.ua_from_json(dev)
    F.OFF_MINUTES, F.OFF_LABEL = 330, "+0530"
    F.ADD_IDFA = False
    F.USE_PROXY = False
    print("[v2] waiting 30s CTIT...", flush=True)
    time.sleep(30)
    ins = F.fmt(int(t_click) + 35, 774)
    s2, r2 = F.api_session(gps, auid, ins)
    print("[v2] CRAFTED SESSION:", s2, r2[:200], flush=True)
    res["session"] = [s2, r2[:300]]
    # NO sdk_click, NO crafted attribution — win-path shape.

    res.update(gps=gps, auid=auid)
    json.dump(res, open(OUT, "w"), indent=1)

    # 4) wipe + launch + app reads the verdict (win path)
    su("am force-stop %s" % PKG)
    su("rm -rf /data/data/%s/files /data/data/%s/shared_prefs "
       "/data/data/%s/databases" % (PKG, PKG, PKG))
    time.sleep(1)
    adb("shell", "am start -n %s/.ui.main.MainActivity" % PKG)
    print("[v2] app launched; reading verdict...", flush=True)

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
        print("  tracker_name=%s inst=%s" % (verdict.get("tracker_name"),
                                             verdict.get("installed_at")))
    else:
        print("VERDICT: none yet after 120s")
    res["verdict_device_oracle"] = verdict
    json.dump(res, open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()
