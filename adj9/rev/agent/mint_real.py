"""Mint a REAL device signature by loading the compiled agent (sign_bundle.js),
which bundles frida-java-bridge. Prints the Authorization + canonical + blob.
"""
import json
import os
import sys
import threading
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = os.path.join(HERE, "sign_bundle.js")
PARAMS = os.path.join(HERE, "..", "..", "device", "params_gold.json")
HOST = "127.0.0.1:27042"
PKG = "com.penti.app"


def main():
    with open(PARAMS, encoding="utf-8") as f:
        p = json.load(f)
    dev = frida.get_device_manager().add_remote_device(HOST)
    pid = None
    for pr in dev.enumerate_processes():
        if "penti" in pr.name.lower():
            pid = pr.pid
            break
    if pid is None:
        print("app not running"); return 1
    print("attach pid", pid)
    sess = dev.attach(pid)
    with open(BUNDLE, encoding="utf-8") as f:
        js = f.read()
    sc = sess.create_script(js)
    ready = threading.Event()

    def on_msg(msg, data):
        if msg["type"] == "send":
            pl = msg["payload"]
            if pl.get("type") == "ready":
                print("[ready] errors:", pl.get("errors"))
                ready.set()
            elif pl.get("type") == "canonical":
                print("[canonical len]", len(pl.get("value") or ""))
            elif pl.get("type") == "header":
                print("[app header]", (pl.get("value") or "")[:120])
            elif pl.get("type") == "nSign":
                print("[app nSign outLen]", pl.get("outLen"))
        elif msg["type"] == "error":
            print("[frida-error]", msg.get("description")); ready.set()
        elif msg["type"] == "log":
            print("[agent]", msg.get("payload"))

    sc.on("message", on_msg)
    sc.load()
    if not ready.wait(timeout=40):
        print("[warn] not ready in 40s")
    else:
        print("[ok] agent ready, minting...")
    try:
        res = sc.exports_sync.mint({"activity": p["activity"],
                                     "globals": p.get("globals", {})})
    except Exception as e:
        print("mint error:", e); sess.detach(); return 1
    if not res.get("ok"):
        print("MINT FAILED:", res.get("error")); print(res.get("stack", "")[:1200])
        sess.detach(); return 1
    print("\n=== REAL authorization ===")
    print(res["authorization"])
    print("blobLen:", res.get("blobLen"))
    with open(os.path.join(HERE, "..", "..", "device", "real_auth.txt"), "w") as f:
        f.write(res["authorization"])
    if res.get("canonical"):
        with open(os.path.join(HERE, "..", "..", "device", "real_canonical.txt"), "w") as f:
            f.write(res["canonical"])
        print("canonical saved (len %d)" % len(res["canonical"]))
    sess.detach()
    return 0


if __name__ == "__main__":
    sys.exit(main())
