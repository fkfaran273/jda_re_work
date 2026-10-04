"""Watch one natural app sign: does the app's OWN signer emit an authorization
under frida? If yes, the signer works and we inject params into the map. If no,
the signer is disabled under instrumentation."""
import json, os, subprocess, time
import frida
HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = os.path.join(HERE, "..", "rev", "agent", "mintcl.js")
SERIAL = "ZD2228MY3X"; PKG = "com.penti.app"
def sh(*a):
    return subprocess.run(list(a), capture_output=True, text=True,
                          env={**os.environ, "MSYS_NO_PATHCONV": "1"})
def app_pid():
    p = sh("adb", "-s", SERIAL, "shell", "su -c 'ps -A | grep com.penti.app'")
    for ln in p.stdout.splitlines():
        pr = ln.split()
        if len(pr) >= 2 and pr[1].isdigit(): return int(pr[1])
    return None
def prep():
    sh("adb", "-s", SERIAL, "shell",
       "su -c 'pkill -9 frida-server; pkill -9 com.penti.app; sleep 1; "
       "setsid /data/local/tmp/frida-server >/dev/null 2>&1 </dev/null &'")
    time.sleep(2)
    sh("adb", "-s", SERIAL, "forward", "tcp:27042", "tcp:27042")
    sh("adb", "-s", SERIAL, "shell", f"am start -n {PKG}/.ui.main.MainActivity")
    for _ in range(12):
        time.sleep(1)
        p = app_pid()
        if p: return p
def main():
    pid = prep(); print("pid", pid)
    if not pid: return 1
    dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    sess = dev.attach(pid)
    with open(BUNDLE, encoding="utf-8") as f: sc = sess.create_script(f.read())
    seen = {"sign": None}
    def on_msg(m, d):
        if m.get("type") == "send":
            p = m.get("payload", {})
            if p.get("type") == "app-sign":
                seen["sign"] = p
                print("[app sign] keys=%s injected=%s auth=%s" % (
                    list((p.get("act") or {}).keys())[:12], p.get("injected"),
                    (p.get("auth") or "NONE")[:60]))
    sc.on("message", on_msg)
    sc.load()
    # installCapture runs in health; call health to install hooks
    try: sc.exports_sync.health()
    except Exception as e: print("health err", e)
    for i in range(30):
        time.sleep(0.4)
        if seen["sign"]:
            break
    r = sc.exports_sync.lastResult()
    print("lastResult auth:", (r.get("auth") or "NONE")[:80])
    print("act keys:", list((r.get("act") or {}).keys()))
    with open(os.path.join(HERE, "watch_result.json"), "w", encoding="utf-8") as f:
        json.dump(r, f, indent=1)
    try: sess.detach()
    except Exception: pass
if __name__ == "__main__":
    main()
