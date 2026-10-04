#!/usr/bin/env python3
"""key2_run.py — run key2_hook.js against com.penti.app, collect (msg,H) pairs.
Flow: wipe Adjust state -> frida spawn (gated) -> resume -> app signs session
pairs stream to key2_pairs.jsonl.  Also polls the stored verdict afterwards."""
import frida, sys, time, json, base64, os, subprocess
sys.stdout.reconfigure(line_buffering=True)
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "key2_pairs.jsonl")
if os.path.exists(OUT):
    os.remove(OUT)

ADB = "adb"
PKG = "com.penti.app"

def sh(cmd):
    return subprocess.run([ADB, "shell", cmd], capture_output=True, text=True, timeout=30).stdout

print("[*] wiping Adjust state")
sh("/debug_ramdisk/su -c 'rm -f /data/data/com.penti.app/files/AdjustIoActivityState /data/data/com.penti.app/files/AdjustAttribution'")
sh("am force-stop com.penti.app")
time.sleep(1)
sh("am start -n com.penti.app/.ui.main.MainActivity")
time.sleep(6)

js = open(os.path.join(HERE, "key2_hook.js"), encoding="utf-8").read()
dev = frida.get_device_manager().add_remote_device("127.0.0.1:4777")
pid = None
for _ in range(15):
    r = subprocess.run([ADB, "shell", "pidof com.penti.app"], capture_output=True, text=True).stdout.strip()
    if r:
        pid = int(r.split()[0])
        break
    sh("am start -n com.penti.app/.ui.main.MainActivity")
    time.sleep(2)
if pid is None:
    sys.exit("no app process")
print(f"[*] waiting 25s for guard window to pass (pid {pid})")
time.sleep(25)
r = subprocess.run([ADB, "shell", "pidof com.penti.app"], capture_output=True, text=True).stdout.strip()
if not r:
    sys.exit("app died while waiting")
pid = int(r.split()[0])
sh("/debug_ramdisk/su -c 'setenforce 0'")
print(f"[*] attaching pid {pid}")
try:
    session = dev.attach(pid)
except Exception:
    sh("/debug_ramdisk/su -c 'setenforce 1'")
    raise
sh("/debug_ramdisk/su -c 'setenforce 1'")
script = session.create_script(js)
rows = []

def on_msg(m, data):
    if m.get("type") != "send":
        print("[?]", m)
        return
    p = m["payload"]
    rows.append(p)
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(p) + "\n")
    if p.get("t") == "sign":
        msg = base64.b64decode(p["msg"])
        H = base64.b64decode(p["H"])
        print(f"[sign] msg {len(msg)}B: {msg[:220]!r}")
        print(f"       H  = {H.hex()}")
    else:
        print(f"[{p.get('t')}] {p}")

script.on("message", on_msg)
script.load()
print("[*] hooked; triggering resume signings in the LIVE aged process")
sh("input keyevent KEYCODE_HOME")
time.sleep(4)
sh("am start -n com.penti.app/.ui.main.MainActivity")
time.sleep(12)
sh("input keyevent KEYCODE_HOME")
time.sleep(4)
sh("am start -n com.penti.app/.ui.main.MainActivity")
print("[*] resumed; capturing 30s ...")
t0 = time.time()
while time.time() - t0 < 35:
    time.sleep(1)
print(f"[*] captured {sum(1 for r in rows if r.get('t')=='sign')} signing(s)")
try:
    session.detach()
except Exception:
    pass
print("[*] verdict file:")
print(sh("/debug_ramdisk/su -c 'cat /data/data/com.penti.app/files/AdjustAttribution'"))