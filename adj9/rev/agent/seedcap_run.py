"""seedcap_run.py — drive the compiled seed-capture agent (seedcap.js).

Spawns com.penti.app, loads the bundled agent (frida-java-bridge + foldhook
native hooks incl. the raw #10 hook), mints N real signatures via the SDK's own
Signer.sign, and writes per-run {seed, desc10, blob} to seedcap_capture.json.

Per run the agent's LOG is reset, so each run's events are same-signing.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import struct
import sys
import threading
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = os.path.join(HERE, "seedcap.js")
PARAMS = os.path.join(HERE, "..", "..", "device", "params_gold.json")
HOST = "127.0.0.1:27042"
PKG = "com.penti.app"

# Realistic params; content does not matter for the byte-exact test, only that
# the SDK produces a normal 192-byte envelope.
GLOBALS = {
    "activity_kind": "session",
    "client_sdk": "android5.7.0",
    "app_version": "3.12.1",
    "package_name": "com.penti.app",
    "os_name": "android",
    "os_version": "12",
    "device_type": "phone",
    "device_name": "moto g42",
    "device_manufacturer": "motorola",
    "country": "TR",
    "language": "tr",
    "android_id": "6d7f0a1b2c3d4e5f",
    "api_level": "31",
    "created_at": "2026-09-24T19:20:00.000Z+0530",
}
ACTIVITY = {"tracker_token": "", "tracker_name": "", "network_payload": "", "endpoint": "/session"}


def seed_from_outhex(out_hex):
    # get8random writes 8 bytes; wrapper takes the low LE 32-bit word.
    b = bytes.fromhex(out_hex)
    return struct.unpack_from("<I", b, 0)[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2)
    ap.add_argument("--attach", action="store_true",
                    help="attach to the already-running app (SDK guard set, libsigner loads on first mint)")
    ap.add_argument("--out", default=os.path.join(HERE, "seedcap_capture.json"))
    a = ap.parse_args()

    with open(PARAMS, encoding="utf-8") as f:
        gold = json.load(f)
    ACTIVITY = gold["activity"]
    GLOBALS = gold["globals"]

    dev = frida.get_device_manager().add_remote_device(HOST)
    if a.attach:
        pid = None
        for pr in dev.enumerate_processes():
            if "penti" in (pr.name or "").lower():
                pid = pr.pid
                break
        if pid is None:
            print("[seedcap] %s not running" % PKG, flush=True)
            return 2
        print("[seedcap] attaching to pid %d" % pid, flush=True)
        sess = dev.attach(pid)
        time.sleep(1.0)
    else:
        print("[seedcap] spawning %s" % PKG, flush=True)
        pid = dev.spawn([PKG])
        sess = dev.attach(pid)
        # Resume first, let ART come up, then load the bundled agent.
        dev.resume(pid)
        time.sleep(3.0)

    native_ready = threading.Event()
    java_ready = threading.Event()
    stream = []

    with open(BUNDLE, encoding="utf-8") as f:
        js = f.read()
    sc = sess.create_script(js)

    def on_msg(msg, data):
        if msg.get("type") == "send":
            p = msg.get("payload") or {}
            stream.append(p)
            k = p.get("type")
            if k == "native_ready":
                print("[seedcap] native base %s" % p.get("base"), flush=True)
                native_ready.set()
            elif k == "java_ready":
                print("[seedcap] java ready", flush=True)
                java_ready.set()
            elif k == "hookfail":
                print("[seedcap] HOOKFAIL %s: %s" % (p.get("what"), p.get("err")), flush=True)
        elif msg.get("type") == "error":
            print("[seedcap] frida error:", msg.get("description"), flush=True)

    sc.on("message", on_msg)
    sc.load()
    # In attach mode libsigner loads lazily on the first mint, so don't block
    # long on native_ready; the first mint forces the load, later mints get
    # captured. In spawn mode libsigner is already present.
    native_ready.wait(timeout=(3 if a.attach else 60))
    java_ready.wait(timeout=25)

    runs = []
    for i in range(a.n):
        if i > 0:
            time.sleep(1.5)   # let tick() install native hooks after load
        try:
            res = sc.exports_sync.mint({"activity": dict(ACTIVITY), "globals": dict(GLOBALS)})
        except Exception as e:
            print("[seedcap] mint %d raised: %s" % (i, e), flush=True)
            break
        evs = res.get("events") or []
        seeds = [seed_from_outhex(e["out"]) for e in evs if e.get("type") == "seed" and e.get("out")]
        d10 = [e for e in evs if e.get("type") == "desc10"]
        blobs = [e for e in evs if e.get("type") == "nsign" and e.get("outB64")]
        print("[seedcap] run %d ok=%s seeds=%s d10=%d blobs=%d" %
              (i, res.get("ok"), [hex(s) for s in seeds], len(d10), len(blobs)), flush=True)
        if res.get("error"):
            print("[seedcap] mint error:", res.get("error"), flush=True)
            print((res.get("stack") or "")[:600], flush=True)
        row = {
            "i": i,
            "ok": res.get("ok"),
            "authorization": res.get("authorization"),
            "seeds_u32": seeds,
            "desc10": [{"length": e.get("length"), "hex": e.get("hex")} for e in d10],
            "blob_b64": blobs[0]["outB64"] if blobs else None,
            "blob_hex": base64.b64decode(blobs[0]["outB64"]).hex() if blobs else None,
            "events": evs,
        }
        runs.append(row)

    with open(a.out, "w", encoding="utf-8") as f:
        json.dump({"stream": stream, "runs": runs}, f, indent=1)
    print("[seedcap] wrote %s" % a.out, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
