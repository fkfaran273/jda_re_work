# mint4_run.py - corrected decisive test: mint OUR map via the SDK's OWN
# Signer.sign (mint2 RPC) instead of mint3's broken direct nlh.a() call.
import base64, datetime as dt, json, os, subprocess, sys, threading, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
AGJS = os.path.join(HERE, "agent", "adj9agent.js")
OUT = os.path.join(HERE, "minted4.json")
import frida
OFF_MIN, OFF_LABEL = 330, "+0530"

def fmt(ts, ms):
    d = dt.datetime.fromtimestamp(ts, dt.timezone.utc) + dt.timedelta(minutes=OFF_MIN)
    return d.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms + "Z" + OFF_LABEL)

def sh(cmd):
    return subprocess.run(["adb", "shell", cmd], capture_output=True, text=True,
                          timeout=30).stdout

ev = {"sigmap": None, "piggy": [], "canonical": [], "nsign": [], "sigpairs": []}
GOT, READY, PIGGY = threading.Event(), threading.Event(), threading.Event()

def on_msg(m, data):
    if m.get("type") != "send":
        print("[?]", str(m)[:200]); return
    p = m.get("payload", {}); t = p.get("type")
    if t == "sigmap":
        ev["sigmap"] = {"activity": p.get("activity"), "globals": p.get("globals")}
        GOT.set()
        print("[sigmap] act=%d glob=%d" % (len(p.get("activity") or {}), len(p.get("globals") or {})))
    elif t == "sigpairs":
        ev["sigpairs"].append(p.get("pairs"))
        print("[sigpairs] %d pairs" % len(p.get("pairs") or []))
    elif t == "canonical":
        ev["canonical"].append(p.get("value"))
        print("[canonical]", str(p.get("value"))[:160])
    elif t == "nSign":
        ev["nsign"].append(p.get("b64"))
        print("[nSign %s B]" % p.get("outLen"))
    elif t == "piggy":
        ev["piggy"].append(p.get("result"))
        print("[piggy %d]" % len(ev["piggy"]), str(p.get("result"))[:300])
    else:
        if t == "ready":
            READY.set()
        print("[ev]", str(p)[:160])

def restart_frida():
    subprocess.run(["adb", "shell", "/debug_ramdisk/su -c 'pkill -9 frs64; pkill -9 fs17root'"],
                   capture_output=True)
    time.sleep(1)
    subprocess.Popen(["adb", "shell", "/debug_ramdisk/su -c 'exec /data/local/tmp/fs17root'"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    subprocess.run(["adb", "forward", "tcp:27042", "tcp:27042"], capture_output=True)


def main():
    restart_frida()
    rdev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    sh("/debug_ramdisk/su -c 'am force-stop com.penti.app'")
    time.sleep(1)
    sh("am start -n com.penti.app/.ui.main.MainActivity")
    pid = 0
    for _ in range(30):
        pid = int(sh("pidof com.penti.app").strip() or 0)
        if pid:
            break
        time.sleep(0.3)
    print("[*] pre-guard attach pid", pid)
    sess = None
    for _ in range(8):
        try:
            sess = rdev.attach(pid); break
        except Exception as e:
            print("[!] attach retry:", str(e)[:90]); time.sleep(0.7)
            pid = int(sh("pidof com.penti.app").strip() or 0)
            if not pid:
                sh("am start -n com.penti.app/.ui.main.MainActivity"); time.sleep(0.6)
                pid = int(sh("pidof com.penti.app").strip() or 0)
    if sess is None:
        print("[F] could not attach"); sys.exit(1)
    scr = sess.create_script(open(AGJS, "r", encoding="utf-8").read())
    scr.on("message", on_msg)
    scr.load()
    for _ in range(40):
        if READY.is_set():
            break
        time.sleep(0.5)
    print("[*] ready:", READY.is_set())
    # wait for the app's own signing (sigmap capture) with kickers
    sig = None
    kicked = 0
    for i in range(75):
        if ev["sigmap"]:
            sig = ev["sigmap"]
            break
        if i in (25, 50) and kicked < 2:
            kicked += 1
            print("[*] no signing yet; HOME-cycle kicker", kicked)
            sh("input keyevent KEYCODE_HOME")
            time.sleep(2)
            sh("am start -n com.penti.app/.ui.main.MainActivity")
        time.sleep(1)
    if sig is None:
        cap = scr.exports_sync.lastcapture()
        if cap and cap.get("lastSigMap"):
            sig = {"activity": cap["lastSigMap"].get("activity"),
                   "globals": cap["lastSigMap"].get("globals")}
    if sig is None:
        print("[F] no real sigmap captured")
        sess.detach()
        sys.exit(2)
    print("[*] piggy channel armed; waiting for 2 same-map mints (E1 diff)")
    deadline = time.time() + 300
    while len(ev["piggy"]) < 2 and time.time() < deadline:
        time.sleep(1)
    mints = []
    for p in ev["piggy"][:2]:
        auth = p.get("auth") or ""
        b64s = auth.split('signature="')[1].split('"')[0] if 'signature="' in auth \
            else p.get("blobB64")
        blob = base64.b64decode(b64s) if b64s else None
        print("[piggy blob] len=%d stamp=%s" % (len(blob) if blob else 0,
                                                p.get("stamp")))
        mints.append({"authorization": auth, "blob_b64": b64s,
                      "blob_hex": blob.hex() if blob else None,
                      "canonical": p.get("canonical"),
                      "stamp": p.get("stamp"),
                      "mapPairs": p.get("mapPairs")})
    blobs = [base64.b64decode(m["blob_b64"]) for m in mints if m["blob_b64"]]
    diffinfo = {"count": len(blobs)}
    if blobs:
        same = all(b == blobs[0] for b in blobs)
        diffinfo["all_identical"] = same
        if not same and len(blobs) >= 2:
            idx = sorted({i for j in range(1, len(blobs))
                          for i in range(min(len(blobs[0]), len(blobs[j])))
                          if blobs[j][i] != blobs[0][i]})
            diffinfo["diff_bytes"] = idx
            diffinfo["diff_dwords"] = sorted({i // 4 for i in idx})
        print("[diff]", json.dumps(diffinfo))
    rec = {"mints": mints, "diff": diffinfo, "sigmap": sig,
           "nsign_b64": ev["nsign"], "sigpairs": ev["sigpairs"]}
    if mints and mints[0]["blob_hex"]:
        rec.update({"blob_hex": mints[0]["blob_hex"], "blob_b64": mints[0]["blob_b64"],
                    "authorization": mints[0]["authorization"]})
    json.dump(rec, open(OUT, "w"), indent=1)
    print("[+] saved", OUT, "mints:", len(mints))
    sess.detach()

if __name__ == "__main__":
    main()
