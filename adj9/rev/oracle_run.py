#!/usr/bin/env python3
"""oracle_run.py — attach sign.js to the aged app process, prove mint(),
and (mode=full) send a device-minted /attribution from Python.
This is the missing-piece test: device signs, Python drives."""
import frida, sys, time, json, os, subprocess, urllib.parse, http.client, ssl, uuid
sys.stdout.reconfigure(line_buffering=True)
HERE = os.path.dirname(os.path.abspath(__file__))
PKG = "com.penti.app"
ADB = "adb"
JS = os.path.join(HERE, "oracle_stealth.js")

def sh(cmd):
    return subprocess.run([ADB, "shell", cmd], capture_output=True, text=True, timeout=30).stdout

def attach():
    dev = frida.get_device_manager().add_remote_device("127.0.0.1:4777")
    pid = None
    for _ in range(15):
        r = subprocess.run([ADB, "shell", "pidof " + PKG], capture_output=True, text=True).stdout.strip()
        if r:
            pid = int(r.split()[0]); break
        sh("am start -n " + PKG + "/.ui.main.MainActivity"); time.sleep(2)
    if pid is None:
        sys.exit("no app process")
    print(f"[*] aging pid {pid} (25s) ...")
    time.sleep(25)
    r = subprocess.run([ADB, "shell", "pidof " + PKG], capture_output=True, text=True).stdout.strip()
    if not r:
        sys.exit("app died while aging")
    pid = int(r.split()[0])
    sh("/debug_ramdisk/su -c 'setenforce 0'")
    print(f"[*] attaching pid {pid} (stealth) ...")
    sess = dev.attach(pid)
    sc = sess.create_script(open(JS, encoding="utf-8").read())
    ready = {}
    sc.on("message", lambda m, d: _onmsg(m, ready))
    sc.load()
    for _ in range(45):
        if ready.get("r"):
            break
        time.sleep(1)
    sh("/debug_ramdisk/su -c 'setenforce 1'")
    alive = sh("pidof " + PKG).strip()
    if not ready.get("r"):
        print("[!] no ready in 45s; alive:", alive)
        sys.exit(2)
    print("[*] agent ready, app alive:", alive)
    return sess, sc


def _onmsg(m, ready):
    p = m.get("payload")
    if isinstance(p, dict):
        t = p.get("type", p.get("t"))
        if t == "ready":
            ready["r"] = True
            print("[js] ready errors:", p.get("errors"))
        elif t == "block":
            print("[js] BLOCK:", str(p.get("note"))[:200])
        elif t == "exception":
            print("[js] EXC:", str(p.get("note"))[:200])
        else:
            print("[js]", t, str(p)[:200])
    else:
        print("[js?]", m.get("type"), str(p)[:200])

def read_state():
    out = {}
    raw = sh("/debug_ramdisk/su -c 'cat /data/data/com.penti.app/files/AdjustIoActivityState'")
    import re
    m = re.search(r"android_uuid=([0-9a-f-]{36})", raw)
    if m: out["auid"] = m.group(1)
    m = re.search(r"gps_adid=([0-9a-f-]{36})", raw)
    if m: out["gps"] = m.group(1)
    return out

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "mint"
    sess, sc = attach()
    api = sc.exports_sync
    print("[health]", api.health())
    st = read_state()
    print("[state]", st)
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z%z", time.gmtime())
    now = now[:-3] + ":00"  # +0000 style like device (+0530 would be +0530)
    act = {
        "initiated_by": "sdk", "gps_adid_attempt": "1", "api_level": "31",
        "app_version": "3.13.9", "app_token": "jut9tib0eeps", "os_version": "12",
        "created_at": now, "device_type": "phone", "gps_adid": st.get("gps", ""),
        "foreground": "1", "android_uuid": st.get("auid", ""), "sent_at": now,
        "offline_mode_enabled": "0", "device_name": "moto g42",
        "environment": "production", "needs_response_details": "1",
        "attribution_deeplink": "1", "package_name": "com.penti.app",
    }
    r = api.mint({"activity": act, "globals": {"activity_kind": "attribution",
                                               "client_sdk": "android5.7.0"}})
    print("[mint] ok:", r.get("ok"), "blobLen:", r.get("blobLen"),
          "err:", r.get("error"))
    print("[mint] canonical:", (r.get("canonical") or "")[:300])
    print("[mint] authorization:", (r.get("authorization") or "")[:120])
    json.dump({"act": act, "mint": r}, open(os.path.join(HERE, "oracle_mint.json"), "w"), indent=1)