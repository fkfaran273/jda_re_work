"""collect_spawn.py — spawn-gated native capture.

force-stops the app, clears Adjust's once-per-launch state so a fresh session is
produced, spawns com.penti.app, loads the native-only agent BEFORE resume
(inject ahead of the guard), resumes, and collects per-signing (S, d10, second)
rows. The LSPosed module logs the matching 192-byte blob independently.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import subprocess

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = "127.0.0.1:27042"
PKG = "com.penti.app"


def adb(*a):
    return subprocess.run(["adb"] + list(a), capture_output=True).stdout.decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--secs", type=float, default=60.0)
    ap.add_argument("--min-rows", type=int, default=0)
    ap.add_argument("--out", default=os.path.join(HERE, "rows.json"))
    a = ap.parse_args()

    rows = []
    js = open(os.path.join(HERE, "foldhook_native.js"), encoding="utf-8").read()
    dev = frida.get_device_manager().add_remote_device(HOST)

    def on_msg(m, d):
        p = m.get("payload") or {}
        t = p.get("type")
        if t == "native_ready":
            print("[spawn] native hooks base=%s" % p.get("base"), flush=True)
        elif t == "sign_row":
            rows.append(p)
            head = [h.get("w1") for h in p.get("head") or []]
            clock = p.get("clock") or []
            fill = clock[-1] if clock else None
            print("[spawn] ROW id=%s sec=%s S=0x%08x d10len=%s ctx_match=%s "
                  "head=%s V=%s" %
                  (p.get("sign_id"), p.get("second"), (p.get("S") or 0),
                   p.get("d10_len"), p.get("ctx_match"),
                   " ".join("%02x" % x for x in head),
                   ("0x%08x" % fill["V"]) if fill else None), flush=True)
        elif t == "guard_err":
            print("[spawn] guard_err %s" % p.get("error"), flush=True)

    # clean slate + clear Adjust launch state so a session is produced
    adb("shell", "su", "-c", "am force-stop %s" % PKG)
    time.sleep(1.5)
    adb("shell", "su", "-c", "rm -f /data/data/%s/shared_prefs/AdjustIoActivityState.xml" % PKG)
    adb("shell", "su", "-c", "rm -f /data/data/%s/files/AdjustIoActivityState" % PKG)

    pid = dev.spawn([PKG])
    sess = dev.attach(pid)
    sc = sess.create_script(js)
    sc.on("message", on_msg)
    sc.load()
    dev.resume(pid)
    print("[spawn] spawned+resumed pid=%d, listening %.0fs" % (pid, a.secs), flush=True)

    t0 = time.time()
    while time.time() - t0 < a.secs:
        if a.min_rows and len(rows) >= a.min_rows:
            break
        time.sleep(0.25)

    with open(a.out, "w", encoding="utf-8") as f:
        json.dump({"rows": rows}, f, indent=1)
    print("[spawn] captured %d rows -> %s" % (len(rows), a.out), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
