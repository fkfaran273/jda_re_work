"""Probe the real device signer: wait for the app to sign naturally (capturing
its live, initialized Signer instance), then immediately mint with that instance.

Anti-frida destroys the script within ~1-2s of attach, so we poll tightly from
Python (non-blocking) and retry the whole attach a few times.
"""
import json, os, subprocess, sys, time
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
        parts = ln.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
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
        pid = app_pid()
        if pid: return pid
    return None

def one_attempt(attempt):
    pid = prep()
    if not pid:
        print("  could not start app"); return None
    dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    sess = dev.attach(pid)
    with open(BUNDLE, encoding="utf-8") as f:
        sc = sess.create_script(f.read())
    def on_msg(m, d):
        if m.get("type") == "send":
            p = m.get("payload", {})
            if p.get("type") == "app-sign":
                print("   [app natural sign] actKeys:", list((p.get("act") or {}).keys())[:10])
    sc.on("message", on_msg)
    sc.load()
    try:
        # mint directly with a fresh instance; the agent polls the static
        # guard Signer.c until the native lib is loaded.
        minimal = {"app_token": "jut9tib0eeps", "activity_kind": "session", "client_sdk": "android5.0.0"}
        r = sc.exports_sync.mint({"activity": minimal,
                                  "globals": {"activity_kind": "session", "client_sdk": "android5.0.0"}})
        summary = {k: r.get(k) for k in ("ok", "stage", "usedAppSigner", "guardC",
                                          "error", "eClass", "eMsg", "canonicalLen", "resKeys")}
        print("   mint:", json.dumps(summary))
        if r.get("stack"):
            print("   java stack:", r["stack"][:300])
        if r.get("authorization"):
            print("   AUTH:", r["authorization"][:120])
        if r.get("canonical"):
            with open(os.path.join(HERE, "probe_canonical.txt"), "w", encoding="utf-8") as f:
                f.write(r["canonical"])
            print("   canonical (first 240):", r["canonical"][:240])
        sess.detach()
        return r
    except Exception as e:
        print("   attempt exc:", type(e).__name__, e)
        try: sess.detach()
        except Exception: pass
        return None

def main():
    for a in range(1, 5):
        print("attempt", a)
        r = one_attempt(a)
        if r and r.get("ok"):
            print("SUCCESS")
            return 0
    print("all attempts failed")
    return 1

if __name__ == "__main__":
    sys.exit(main())
