#!/usr/bin/env python3
"""mint_run.py — attach to aged com.penti.app with sign.js, capture the app's own
canonical+blob, then MINT a signature with custom params via the app's key2."""
import frida, sys, time, json, os, subprocess, base64
sys.stdout.reconfigure(line_buffering=True)
HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(HERE, "agent", "adj9agent.js")
ADB = "adb"

def sh(cmd):
    return subprocess.run([ADB, "shell", cmd], capture_output=True, text=True, timeout=30).stdout

cap = {"canonical": [], "header": [], "nSign": []}
READY = __import__("threading").Event()
def on_msg(m, data):
    if m.get("type") != "send":
        print("[?]", str(m)[:200]); return
    p = m["payload"]; t = p.get("type")
    if t == "canonical":
        cap["canonical"].append(p["value"])
        print(f"[canonical {len(p['value'])}B] {p['value'][:250]}")
    elif t == "header":
        cap["header"].append(p["value"]); print(f"[header blobLen={p['blobLen']}]")
    elif t == "nSign":
        cap["nSign"].append(p["b64"]); print(f"[nSign {p['outLen']}B]")
    else:
        if t == "ready":
            READY.set()
        print("[ev]", str(p)[:160])

# mint payload: overrides on top of the REAL captured map
gps = "f476b3d4-e0b1-4707-bc43-6153d17f7f8c"
auid = "1f4b5b1e-6498-4aaa-b9ab-0b961e7a7b01"
now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z+0530", time.gmtime(time.time() + 19800))
MINTPAY = {"activity": {"created_at": now, "sent_at": now,
                        "activity_kind": "attribution"},
           "globals": {"client_sdk": "android5.7.0"}}
SIGMAP = __import__("threading").Event()
_orig = on_msg
def on_msg(m, data):
    _orig(m, data)
    try:
        if m.get("type") == "send" and m["payload"].get("type") == "sigmap":
            SIGMAP.set()
    except Exception:
        pass

r = subprocess.run([ADB, "shell", "pidof com.penti.app"], capture_output=True, text=True).stdout.strip()
if not r:
    sh("am start -n com.penti.app/.ui.main.MainActivity"); time.sleep(8)
    r = subprocess.run([ADB, "shell", "pidof com.penti.app"], capture_output=True, text=True).stdout.strip()
pid = int(r.split()[0])

# server: fs17root (v17.17.0) matches C:\Python314's frida 17.17.0 client
# (the 00:09 working pair). frs64 (16.4.8) must not hold the port.
subprocess.run([ADB, "shell", "/debug_ramdisk/su -c 'pkill -9 frs64; pkill -9 fs17root'"], capture_output=True)
time.sleep(1)
subprocess.Popen([ADB, "shell", '/debug_ramdisk/su -c "exec /data/local/tmp/fs17root"'],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
dev = None
for _ in range(15):
    time.sleep(2)
    try:
        dev = frida.get_usb_device(timeout=5)
        dev.enumerate_processes()
        break
    except Exception:
        pass
if dev is None:
    sys.exit("no frida server")
sh("am force-stop com.penti.app")
sh("/debug_ramdisk/su -c 'rm -f /data/data/com.penti.app/files/AdjustIo*'")
time.sleep(1)
sh("am start -n com.penti.app/.ui.main.MainActivity")
pid = None
for _ in range(20):
    time.sleep(0.5)
    r = sh("pidof com.penti.app").strip()
    if r:
        pid = int(r.split()[0]); break
print(f"[*] attaching pid {pid} immediately (pre-guard)")
import frida as _f
print("[*] client frida:", _f.__version__)
# SELinux must be permissive for the helper's ptrace (the 00:09 success had it so)
sh("/debug_ramdisk/su -c 'setenforce 0'")
session = None
for attempt in range(5):
    try:
        session = dev.attach(pid)
        break
    except Exception as e:
        print(f"[!] attach attempt {attempt + 1} failed: {type(e).__name__}: {str(e)[:120]}")
        time.sleep(1)
        sh("am force-stop com.penti.app")
        time.sleep(1)
        sh("am start -n com.penti.app/.ui.main.MainActivity")
        for _ in range(20):
            time.sleep(0.5)
            r = sh("pidof com.penti.app").strip()
            if r:
                pid = int(r.split()[0])
                break
if session is None:
    sys.exit("attach failed 5x")
print("[*] attached")
js = open(DEV, encoding="utf-8").read()
script = session.create_script(js)
script.on("message", on_msg)
script.load()
if not READY.wait(timeout=12):
    print("[!] agent never became ready; trying anyway")

# 1) trigger the app's OWN signing (captures real map + own triplet) — stays in-process
sh("input keyevent KEYCODE_HOME"); time.sleep(3)
sh("am start -n com.penti.app/.ui.main.MainActivity"); time.sleep(10)
SIGMAP.wait(timeout=5)

# 2) MINT immediately on top of the captured real map
try:
    out = script.exports_sync.mint2(MINTPAY)
except Exception as e:
    print("[!] mint rpc failed:", type(e).__name__, str(e)[:120])
    out = None
print("[mint] ok:", (out or {}).get("ok"), "err:", (out or {}).get("error"))
for k, v in zip((out or {}).get("resKeys") or [], (out or {}).get("resVals") or []):
    print(f"   res[{k}] = {str(v)[:160]}")
if out and out.get("ok"):
    res = {"authorization": out["authorization"], "canonical": out.get("canonical"),
           "params": MINTPAY}
    json.dump(res, open(os.path.join(HERE, "minted.json"), "w"), indent=1)
    print("[mint] authorization saved to minted.json")
    print("  auth:", out["authorization"][:120], "…")
    if out.get("canonical"):
        print("  canon:", out["canonical"][:200], "…")
json.dump(cap, open(os.path.join(HERE, "own_capture.json"), "w"), indent=1)
print("[*] own signings while alive: canon=%d nSign=%d" % (len(cap['canonical']), len(cap['nSign'])))
time.sleep(1)
try:
    session.detach()
except Exception:
    pass