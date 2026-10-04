"""capture_rows.py — foldhook-only: capture the DEVICE's own d0 + head, no mint.

paired_mint.py's mint RPC (mintcl) can destroy the Frida script before the app's
own signings land, and we do not need the RPC for the head question: the app
signs on its own at startup.  This driver loads foldhook_native.js alone and
records every sign_row, which is exactly the ground truth the head tables must
match.

Usage:  python capture_rows.py [seconds]
"""
import json
import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
SERIAL = "ZD2228MY3X"
PKG = "com.penti.app"
HOST = "127.0.0.1:27042"
FOLDHOOK = os.path.join(HERE, "bridge", "foldhook_native.js")
OUT = os.path.join(HERE, "artifacts", "live_rows.json")

sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")


def main():
    secs = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    import subprocess
    subprocess.run(["adb", "-s", SERIAL, "shell", "su", "-c",
                    "am force-stop %s" % PKG], capture_output=True)
    time.sleep(1.0)
    # Wipe the SDK's own attribution state, otherwise the app considers itself
    # already-attributed and never signs a fresh session, so we capture nothing.
    subprocess.run(["adb", "-s", SERIAL, "shell", "su", "-c",
                    "rm -f /data/data/%s/files/AdjustIo* "
                    "/data/data/%s/shared_prefs/AdjustIo*" % (PKG, PKG)],
                   capture_output=True)

    dev = frida.get_device_manager().add_remote_device(HOST)
    pid = dev.spawn([PKG])
    sess = dev.attach(pid)
    rows = []

    def on_msg(m, d):
        if m.get("type") != "send":
            return
        p = m.get("payload") or {}
        if p.get("type") == "sign_row":
            rows.append(p)
            print("[row] sign_id=%s sec=%s S=0x%08x d10=%sB head=%s"
                  % (p.get("sign_id"), p.get("second"), p.get("S") or 0,
                     p.get("d10_len"),
                     " ".join("%02x" % (h.get("w1") or 0) for h in (p.get("head") or []))),
                  flush=True)

    sc = sess.create_script(open(FOLDHOOK, encoding="utf-8").read())
    sc.on("message", on_msg)
    sc.load()
    dev.resume(pid)
    print("[prep] resumed, collecting %ds" % secs, flush=True)

    t0 = time.time()
    while time.time() - t0 < secs:
        time.sleep(1.0)
    try:
        rows = sc.exports_sync.rows() or rows
    except Exception:
        pass
    json.dump({"ts": time.time(), "rows": rows}, open(OUT, "w", encoding="utf-8"),
              indent=1)
    print("[save] %s  rows=%d" % (OUT, len(rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
