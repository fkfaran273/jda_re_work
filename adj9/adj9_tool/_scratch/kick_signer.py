"""Run the init-chain 'kick' probe to find what flips Signer.c=true."""
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
    sc.on("message", lambda m, d: None)
    sc.load(); time.sleep(0.4)
    r = sc.exports_sync.kick()
    print(json.dumps(r, indent=1))
    with open(os.path.join(HERE, "kick_result.json"), "w", encoding="utf-8") as f:
        json.dump(r, f, indent=1)
    try: sess.detach()
    except Exception: pass
if __name__ == "__main__":
    main()
