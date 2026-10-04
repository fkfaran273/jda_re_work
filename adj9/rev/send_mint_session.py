# send_mint_session.py — send the DEVICE-MINTED session blob (from the piggy's
# mint_out*.json on the device) to /session via the DEVICE transport, then poll.
import base64
import json
import os
import subprocess
import sys
import time
import uuid

HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev"
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import adj9_full_chain as F
import run_funnel as R
import mint_session_chain as M

DEVFILE = ("/storage/emulated/0/Android/data/com.penti.app/files/"
           "mint_out%d.json")
OUT = os.path.join(HERE, "send_mint_session_result.json")


def pull(n):
    raw = subprocess.run(
        ["adb", "shell", "/debug_ramdisk/su -c 'cat %s'" % DEVFILE % n],
        capture_output=True).stdout.decode("utf-8", "replace")
    i = raw.find("{")
    return json.loads(raw[i:]) if i >= 0 else None


def main():
    dev = json.load(open(os.path.join(HERE, "dev_mi.json"), encoding="utf-8"))
    M.setup_chain(dev)
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    j = pull(n)
    if not j:
        print("[F] no mint_out%d.json on device" % n); sys.exit(1)
    auth = j.get("auth") or ""
    if 'signature="' not in auth:
        print("[F] no signature in mint_out%d" % n); sys.exit(2)
    blob = base64.b64decode(auth.split('signature="')[1].split('"')[0])
    mp = {k: v for k, v in (j.get("mapPairs") or []) if v is not None}
    gps, auid = mp.get("gps_adid"), mp.get("android_uuid")
    print("mint_out%d: blob=%dB kind=%s gps=%s auid=%s stamp=%s keys=%d"
          % (n, len(blob), mp.get("activity_kind"), gps, auid, j.get("stamp"),
             len(mp)), flush=True)
    rec = {"file": n, "blob_hex": blob.hex(), "auth": auth, "gps": gps,
           "auid": auid, "kind": mp.get("activity_kind"), "stamp": j.get("stamp")}
    q = {k: mp[k] for k in M.WIRE if k in mp}
    s, r = F.send_device("https://app.adjust.com/session", q, blob)
    print("SESSION (minted session blob, device transport):", s, str(r)[:250],
          flush=True)
    rec["session"] = [s, str(r)[:600]]
    try:
        ask = json.loads(r).get("ask_in", 0) or 0
    except Exception:
        ask = 0
    if ask:
        w = min(ask / 1000.0, 180.0)
        print("ask_in=%d -> wait %.0fs" % (ask, w), flush=True)
        time.sleep(w)
    ptoken = "e" + uuid.uuid4().hex * 3 + ":APA91b" + uuid.uuid4().hex * 3
    ib = "backend" if ask else "sdk"
    rec["arms"] = []
    for i in (1, 2, 3):
        s2, r2 = F.api_attribution(gps, auid, ptoken, ib)
        try:
            a = json.loads(r2).get("attribution", {})
            v = "%s / %s / eng=%s / inst=%s" % (
                a.get("tracker_token"), a.get("network"),
                a.get("engagement_time"), a.get("installed_at"))
        except Exception:
            v = "HTTP %s %s" % (s2, str(r2)[:150])
        print("ATTR%d: %s" % (i, v), flush=True)
        rec["arms"].append({"http": s2, "verdict": v, "raw": str(r2)[:1500]})
        if i < 3:
            time.sleep(20)
    json.dump(rec, open(OUT, "w"), indent=1)
    print("saved", OUT)


if __name__ == "__main__":
    main()