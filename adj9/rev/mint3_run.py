# mint3_run.py — make the DEVICE signer (real keystore H + native body) sign
# OUR canonical map, save blob; PC then sends it with a matching wire query.
# Decisive test of "server verifies map/bytes (computable), not key2 state".
import json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
AGJS = os.path.join(HERE, "agent", "adj9agent.js")
OUT = os.path.join(HERE, "minted3.json")

GPS = "0e789180-17da-440b-b1c3-0349d40e0e93"
AUID = "205e93a4-56f9-41fd-bfa0-1edbe4245529"      # current install auid
INS = "2026-09-15T23:20:21.431Z+0530"              # install record stamp
NOW = int(time.time())
import datetime as dt
def fmt(ts, ms):
    d = dt.datetime.fromtimestamp(ts, dt.timezone.utc) + dt.timedelta(minutes=330)
    return d.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z+0530")

# /attribution activity map — order here == wire param order == canonical order
pairs = [
    ["initiated_by", "backend"],
    ["gps_adid_attempt", "1"],
    ["api_level", "31"],
    ["app_version", "3.13.9"],
    ["app_token", "jut9tib0eeps"],
    ["os_version", "12"],
    ["created_at", fmt(NOW - 1, 666)],
    ["device_type", "phone"],
    ["gps_adid", GPS],
    ["foreground", "1"],
    ["android_uuid", AUID],
    ["sent_at", fmt(NOW - 1, 696)],
    ["offline_mode_enabled", "0"],
    ["device_name", "moto g42"],
    ["environment", "production"],
    ["needs_response_details", "1"],
    ["attribution_deeplink", "1"],
    ["package_name", "com.penti.app"],
    ["os_name", "android"],
    ["ui_mode", "1"],
    ["gps_adid_src", "service"],
    ["tracking_enabled", "1"],
]
# u2 injects these AFTER the activity params (proved by corpus map_order)
for kv in [("client_sdk", "android5.7.0"),
           ("adj_verification", "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"),
           ("headers_id", "10"), ("algorithm", "adj9"),
           ("adj_signing_id", "1500000"), ("native_version", "5.0.0")]:
    pairs.append(list(kv))

canonical = "{" + ", ".join(f"{k}={v}" for k, v in pairs) + "}"

import frida
dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
os.system('adb shell "/debug_ramdisk/su -c \'am force-stop com.penti.app\'"')
time.sleep(1)
os.system('adb shell "am start -n com.penti.app/.ui.main.MainActivity"')
pid = 0
for _ in range(30):
    pid = int(os.popen('adb shell pidof com.penti.app').read().strip() or 0)
    if pid:
        break
    time.sleep(0.3)
print("[*] pre-guard attach pid", pid)
sess = None
for attempt in range(8):
    try:
        sess = dev.attach(pid)
        break
    except Exception as e:
        print("[!] attach retry:", str(e)[:90])
        time.sleep(0.7)
        pid = int(os.popen('adb shell pidof com.penti.app').read().strip() or 0)
        if not pid:
            os.system('adb shell "am start -n com.penti.app/.ui.main.MainActivity"')
            time.sleep(0.6)
            pid = int(os.popen('adb shell pidof com.penti.app').read().strip() or 0)
if sess is None:
    print("[F] could not attach"); sys.exit(1)
scr = sess.create_script(open(AGJS, "r", encoding="utf-8").read())
ready = {"ok": False}
def on_msg(m, data):
    t = m.get("type")
    if t == "send":
        p = m.get("payload", {})
        if isinstance(p, dict) and p.get("type") == "ready":
            ready["ok"] = True
        print("[ev]", str(p)[:140])
    elif t == "error":
        print("[!]", str(m)[:300])
scr.on("message", on_msg)
scr.load()
for _ in range(40):
    if ready["ok"]:
        break
    time.sleep(0.5)
print("[*] ready:", ready["ok"])
# wait for the sig-SDK classes to load (they appear at the app's first signing)
res = None
for attempt in range(20):
    res = scr.exports_sync.mint3({"canonical": canonical, "pairs": pairs})
    err = (res.get("error") or "")
    if res.get("ok") or "ClassNotFoundException" not in err:
        break
    print("[*] sig classes not up yet, retry", attempt + 1)
    time.sleep(1)
print("[mint3]", {k: (v[:40] + "..." if isinstance(v, str) and len(v) > 40 else v)
                  for k, v in res.items() if k != "blobB64"})
if res.get("ok"):
    json.dump({"canonical": canonical, "pairs": pairs,
               "blob_b64": res["blobB64"], "H": res.get("H"),
               "gps": GPS, "auid": AUID, "now": NOW},
              open(OUT, "w"))
    print("[+] saved", OUT)
sess.detach()
