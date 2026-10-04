"""paired_mint.py — MY decisive paired-mint driver (mywork, 2026-09-27).

One process, two agents, one FIXED map:
  * foldhook_native.js  (loaded FIRST, before resume) — guard swallow +
    per-signing descriptor-plane capture: S, second, all 11 descriptors,
    d10, head (0x1441e4 w1 sequence), gettimeofday clock.
  * mintcl.js           — Java RPC mint: Signer.sign() on OUR map ->
    {authorization, nSignBlob, canonical}.

The map is the PROVEN session wire map from artifacts/adj9_sign_in.pull
(the same map the LSPosed oracle signed for the NON-ORGANIC winning run).

Output: artifacts/paired_mint.json = {map, globals, mint result, new sign_rows}.
Then run diff_paired.py to replay offline with F.py and byte-diff.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
SERIAL = "ZD2228MY3X"
PKG = "com.penti.app"
HOST = "127.0.0.1:27042"
CONTROL = os.path.join(HERE, "artifacts", "adj9_sign_in.pull")
FOLDHOOK = os.path.join(HERE, "bridge", "foldhook_native.js")
MINTCL = os.path.join(HERE, "bridge", "mintcl.js")
OUT = os.path.join(HERE, "artifacts", "paired_mint.json")

sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")


def adb(*a, timeout=30):
    r = subprocess.run(["adb", "-s", SERIAL] + list(a),
                       capture_output=True, timeout=timeout)
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def su(cmd, timeout=30):
    return adb("shell", "su", "-c", cmd, timeout=timeout)


def ensure_frida():
    su("pkill -9 frida-server")
    time.sleep(1)
    subprocess.Popen(
        ["adb", "-s", SERIAL, "shell",
         'su -c "setsid /data/local/tmp/frida-server >/dev/null 2>&1 </dev/null &"'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    adb("forward", "tcp:27042", "tcp:27042")
    for _ in range(20):
        time.sleep(0.5)
        try:
            dev = frida.get_device_manager().add_remote_device(HOST)
            dev.enumerate_processes()
            print("[prep] frida-server up")
            return dev
        except Exception:
            pass
    raise SystemExit("[fatal] no frida-server")


def parse_control(path):
    """First TASK block -> (kind, sdk, {k:v})."""
    tasks, cur = [], None
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\r\n")
        if line.strip() == "TASK":
            cur = {"kind": "session", "sdk": "android5.7.0", "map": {}}
            tasks.append(cur)
            continue
        if cur is None:
            continue
        if line.startswith("KIND="):
            cur["kind"] = line[5:].strip()
        elif line.startswith("SDK="):
            cur["sdk"] = line[4:].strip()
        elif "\x01" in line:
            k, v = line.split("\x01", 1)
            cur["map"][k] = v
    return tasks


def main():
    t = parse_control(CONTROL)
    task = t[0]                       # the session task (43 keys, proven)
    kind, sdk, wire_map = task["kind"], task["sdk"], task["map"]
    marker = wire_map.get("gps_adid", "").encode()
    print("[map] kind=%s sdk=%s keys=%d marker=%s"
          % (kind, sdk, len(wire_map), wire_map.get("gps_adid")))

    dev = ensure_frida()

    # fresh process so the SDK signs its own first session (warms the
    # Signer singleton for mintcl's STATE.appSigner) and guard state is clean
    su("am force-stop %s" % PKG)
    time.sleep(1.0)
    su("rm -f /data/data/%s/files/AdjustIo* /data/data/%s/shared_prefs/AdjustIo*"
       % (PKG, PKG))

    pid = dev.spawn([PKG])
    print("[prep] spawned pid=%d" % pid)
    sess = dev.attach(pid)

    rows = []          # foldhook sign_row events
    events = []        # everything else (diagnostics)

    def on_fold(m, d):
        if m.get("type") != "send":
            return
        p = m.get("payload") or {}
        if p.get("type") == "sign_row":
            rows.append(p)
            head = [h.get("w1") for h in (p.get("head") or [])]
            print("[fold] sign_row #%s sec=%s S=0x%08x d10=%sB head=%s"
                  % (p.get("sign_id"), p.get("second"), p.get("S") or 0,
                     p.get("d10_len"),
                     " ".join("%02x" % (x or 0) for x in head[:8])), flush=True)
        else:
            events.append(p)
            if p.get("type") in ("native_ready", "base", "guard_err",
                                 "clock_ready", "clock_hook_err"):
                print("[fold] %s" % json.dumps(p)[:160], flush=True)

    # 1) foldhook FIRST (guard + native capture live before resume)
    sc1 = sess.create_script(open(FOLDHOOK, encoding="utf-8").read())
    sc1.on("message", on_fold)
    sc1.load()
    # 2) mintcl (Java RPC; ART not touched until we call it)
    sc2 = sess.create_script(open(MINTCL, encoding="utf-8").read())
    sc2.load()
    dev.resume(pid)
    print("[prep] resumed, waiting for native hooks + ART", flush=True)

    # wait for foldhook's native install + clock
    t0 = time.time()
    armed = False
    while time.time() - t0 < 30:
        try:
            if sc1.exports_sync.installed():
                armed = True
                break
        except Exception:
            pass
        time.sleep(0.3)
    print("[fold] installed=%s base=%s" % (armed, sc1.exports_sync.base()))
    if not armed:
        print("[fold] WARN native hooks not installed yet (libsigner late?)")

    # wait for ART + classloader resolve (health installs the capture hook)
    health = None
    t0 = time.time()
    while time.time() - t0 < 30:
        try:
            health = sc2.exports_sync.health()
            if health and health.get("loaderFound"):
                break
        except Exception as e:
            health = {"error": str(e)}
        time.sleep(0.5)
    print("[mint] health=%s" % json.dumps(health)[:300])

    # wait for the app's OWN first sign (warms live Signer instance)
    have_signer = False
    t0 = time.time()
    while time.time() - t0 < 25:
        try:
            lr = sc2.exports_sync.lastResult()
            if lr.get("haveSigner"):
                have_signer = True
                print("[mint] live app Signer captured (act keys=%s)"
                      % len(lr.get("act") or {}))
                break
        except Exception:
            pass
        time.sleep(0.5)
    if not have_signer:
        print("[mint] no live Signer yet — mint() will try $new()+onResume")

    time.sleep(1.0)
    n0 = len(rows)
    print("[mint] signing OUR fixed map ...", flush=True)
    try:
        r = sc2.exports_sync.mint({"activity": wire_map,
                                   "globals": {"activity_kind": kind,
                                               "client_sdk": sdk}})
    except Exception as e:
        r = {"ok": False, "error": "rpc: %s" % e}
    print("[mint] result ok=%s err=%s guardC=%s auth=%dB nSignBlob=%s canon=%s"
          % (r.get("ok"), (r.get("error") or "")[:150], r.get("guardC"),
             len(r.get("authorization") or ""),
             ("present" if r.get("nSignBlob") else "NONE"),
             r.get("canonicalLen")))

    # foldhook rows arrive async via send() — give them a moment.  The app's own
    # signings can happen BEFORE our mint RPC (and the RPC may kill the script),
    # so never rely on rows appearing after n0: fall back to all rows seen.
    time.sleep(2.5)
    new_rows = rows[n0:]
    pool = new_rows if new_rows else rows
    # pair: prefer the row whose d10 contains our marker bytes (gps_adid)
    paired = None
    for rw in pool:
        hx = rw.get("d10_hex") or ""
        try:
            if marker and marker in bytes.fromhex(hx):
                paired = rw
                break
        except Exception:
            pass
    if paired is None and pool:
        paired = pool[-1]
    print("[pair] %d new / %d total rows; paired=%s (sign_id=%s sec=%s)"
          % (len(new_rows), len(pool), paired is not None,
             paired.get("sign_id") if paired else None,
             paired.get("second") if paired else None))

    # sanity: blob header vs paired second
    blob = None
    if r.get("nSignBlob"):
        try:
            nb = r["nSignBlob"]
            blob = base64.b64decode(nb + "=" * (-len(nb) % 4))
        except Exception as e:
            print("[pair] b64 decode failed:", e)
    hdr_ok = None
    if blob and paired:
        sys.path.insert(0, os.path.join(HERE, "signer"))
        from header_gen import make_header
        hdr_ok = (blob[:16] == make_header(paired["second"]))
        print("[pair] blob=%dB header==make_header(second)=%s"
              % (len(blob), hdr_ok))

    out = {
        "ts": time.time(),
        "kind": kind, "sdk": sdk,
        "map": [[k, v] for k, v in wire_map.items()],
        "globals": {"activity_kind": kind, "client_sdk": sdk},
        "mint": r,
        "canonical": r.get("canonical"),
        "blob_hex": blob.hex() if blob else None,
        "header_ok": hdr_ok,
        "new_rows": new_rows,
        "all_rows": pool,
        "paired_row": paired,
        "events": events[-40:],
        "health": health,
    }
    json.dump(out, open(OUT, "w", encoding="utf-8"), indent=1)
    print("[save] %s (%d bytes on disk)"
          % (OUT, os.path.getsize(OUT)))

    try:
        sess.detach()
    except Exception:
        pass
    return 0 if (r.get("ok") and paired) else 1


if __name__ == "__main__":
    sys.exit(main())
