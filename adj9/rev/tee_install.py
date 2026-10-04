#!/usr/bin/env python3
"""tee_install.py — THE decisive test: is a device-minted (mint3) package accepted?

A: fresh GAID + marker click (engagement)
B: app net blocked -> wipe -> relaunch -> app SIGNS but cannot send
   -> capture (pairs, canonical, H, blob, header) = its genuine first package
C: force-stop app; MINT3 an /attribution for the same identity via key2
D: net restored; from Python: send session (books), minted attr, minted attr replay
"""
import base64, json, os, re, subprocess, sys, time, uuid
sys.stdout.reconfigure(line_buffering=True)
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import frida
import farm_win as fw

ADB = "adb"
PKG = "com.penti.app"
OUT = os.path.join(HERE, "tee_result.json")
AGENT = os.path.join(HERE, "agent", "adj9agent.js")

cap = {"sigpairs": [], "canonical": [], "hmac": [], "nSign": [], "header": []}
READY = __import__("threading").Event()
SIGPAIRS = __import__("threading").Event()
MINT = __import__("threading").Event()

def on_msg(m, data):
    if m.get("type") != "send":
        return
    p = m["payload"]; t = p.get("type")
    if t == "mint_result":
        cap["mint"] = p["result"]
        print(f"[mint_result] ok={p['result'].get('ok')} hsrc={p['result'].get('hsrc')} "
              f"blobLen={p['result'].get('blobLen')} err={p['result'].get('error')}")
        MINT.set()
    elif t == "sigpairs":
        kind = dict((kv[0], kv[1]) for kv in p["pairs"]).get("activity_kind", "?")
        cap["sigpairs"].append(p["pairs"])
        cap.setdefault("bykind", {})[kind] = {
            "pairs": p["pairs"], "blob": cap.get("lastNSign")}
        SIGPAIRS.set()
        print(f"[sigpairs] {len(p['pairs'])} pairs kind={kind}")
    elif t == "canonical":
        cap["canonical"].append(p["value"])
        print(f"[canonical] {len(p['value'])}B")
    elif t == "d3":
        cap["canonical"].append(p.get("inStr") or "")
        print(f"[d3] {p.get('sig')} out={p.get('outLen')}B")
    elif t == "macdf":
        cap["hmac"].append({"in": p.get("inB64"), "out": p.get("outB64")})
        print(f"[macdf] alg={p.get('alg')}")
    elif t == "hmac":
        cap["hmac"].append({"in": p["inB64"], "out": p["outB64"]})
        print(f"[hmac] in={len(base64.b64decode(p['inB64'])) if p.get('inB64') else '?'}B")
    elif t == "nSign":
        cap["lastNSign"] = p["b64"]
        cap["nSign"].append(p["b64"]); print(f"[nSign] {p['outLen']}B")
    elif t == "sigpairs":
        # correlate: the nSign emitted just before this sigmap belongs to it
        kind = dict((kv[0], kv[1]) for kv in p["pairs"]).get("activity_kind", "?")
        cap["sigpairs"].append(p["pairs"])
        cap.setdefault("bykind", {})[kind] = {
            "pairs": p["pairs"], "blob": cap.get("lastNSign")}
        SIGPAIRS.set()
        print(f"[sigpairs] {len(p['pairs'])} pairs kind={kind}")
    elif t == "header":
        if p.get("blobB64"):
            cap["nSign"].append(p["blobB64"])
        cap["header"].append(p["value"]); print("[header] captured")
    elif t == "ready":
        READY.set(); print("[ready]", p.get("errors"))
    else:
        print("[ev]", str(p)[:120])

def block_app_net(on, uid):
    if on:
        fw.su(f"iptables -I OUTPUT 1 -m owner --uid-owner {uid} -j REJECT")
    else:
        fw.su(f"iptables -D OUTPUT -m owner --uid-owner {uid} -j REJECT")

def pull_mint_file():
    """Last-resort rescue: the agent persists mint_out.json app-side."""
    p = "/storage/emulated/0/Android/data/com.penti.app/files/mint_out.json"
    fw.su(f"dd if={p} of=/data/local/tmp/mint_out.json 2>/dev/null")
    dst = os.path.join(HERE, "mint_out.json")
    if os.path.exists(dst):
        os.remove(dst)
    subprocess.run(["adb", "pull", "/data/local/tmp/mint_out.json", dst],
                   capture_output=True)
    try:
        d = json.load(open(dst))
        print(f"[mintfile] rescued: ok={d.get('ok')} blobLen={d.get('blobLen')}")
        return d
    except Exception:
        print("[mintfile] no file")
        return None

def send_pkg(url, pairs, blob_b64, auth, method):
    from curl_cffi import requests as cr
    SKIP = {"adj_verification", "client_sdk", "headers_id", "adj_signing_id",
            "native_version", "algorithm", "signature"}
    params = {k: v for k, v in pairs if k not in SKIP and v is not None}
    headers = {"Client-SDK": "android5.7.0", "Authorization": auth,
               "Content-Type": "application/x-www-form-urlencoded",
               "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)",
               "Connection": "Keep-Alive", "Accept-Encoding": "gzip"}
    px = {"http": "http://127.0.0.1:8888", "https": "http://127.0.0.1:8888"}
    if method == "POST":
        r = cr.post(url, data=params, headers=headers, timeout=25,
                    proxies=px, verify=False)
    else:
        r = cr.get(url, params=params, headers=headers, timeout=25,
                   proxies=px, verify=False)
    print(f"[net] {url.rsplit('/',1)[-1]} {method} -> {r.status_code}: {r.text[:200]}")
    return r.status_code, r.text


def auth_from_blob(blob_b64):
    """Authorization header, exact format from the live capture / adj9_full_chain."""
    return ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0"'
            % blob_b64)

def get_agent():
    return open(AGENT, encoding="utf-8").read()

def attach_gated(dev=None):
    """Gated spawn (preferred), with one retry; falls back to aged attach."""
    for attempt in (1, 2):
        fw.su("setenforce 0")
        subprocess.Popen([ADB, "shell",
                          '/debug_ramdisk/su -c "pkill -9 fs17root; pkill -9 frs64; sleep 1; '
                          'setsid /data/local/tmp/fs17root >/dev/null 2>&1 &"'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([ADB, "forward", "tcp:27042", "tcp:27042"], capture_output=True)
        import socket as _s
        ok = False
        for _ in range(10):
            try:
                c = _s.create_connection(("127.0.0.1", 27042), timeout=3); c.close(); ok = True; break
            except Exception:
                time.sleep(2)
        if not ok:
            continue
        if dev is None:
            dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        try:
            sp = dev.spawn([fw.APP])              # suspended
            s = dev.attach(sp)
            script = s.create_script(get_agent())
            script.on("message", on_msg)
            script.load()
            if not READY.wait(15):
                print("[!] agent not ready before resume; resuming anyway")
            dev.resume(sp)                        # hooks armed -> now run
            fw.su("setenforce 1")
            print(f"[*] gated spawn pid {sp} resumed with agent armed")
            return s, script, dev
        except Exception as e:
            print(f"[!] gated spawn attempt {attempt} failed: {str(e)[:90]}")
            time.sleep(2)
    fw.su("setenforce 1")
    # ---- fallback: aged attach (guard window passes, server survives) ----
    print("[*] falling back to AGED ATTACH")
    import socket as _s2

    def ensure_server():
        subprocess.Popen([ADB, "shell",
                          '/debug_ramdisk/su -c "setsid /data/local/tmp/fs17root >/dev/null 2>&1 &"'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([ADB, "forward", "tcp:27042", "tcp:27042"], capture_output=True)
        for _ in range(10):
            try:
                c = _s2.create_connection(("127.0.0.1", 27042), timeout=3); c.close(); return True
            except Exception:
                time.sleep(2)
        return False

    fw.su("setenforce 0")
    fw.su("am start -n %s/.ui.main.MainActivity" % fw.APP)
    for extra in (30, 30, 30):
        time.sleep(extra)
        r = fw.sh("pidof %s" % fw.APP).strip()
        if not r:
            print("[!] app died in fallback; restarting")
            fw.su("am start -n %s/.ui.main.MainActivity" % fw.APP)
            continue
        if not ensure_server():
            print("[!] frida server unreachable in fallback")
            continue
        pid = int(r.split()[0])
        print(f"[*] aged attach attempt pid {pid}")
        try:
            dev2 = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
            s = dev2.attach(pid)
            script = s.create_script(get_agent())
            script.on("message", on_msg)
            script.load()
            READY.wait(15)
            fw.su("setenforce 1")
            print(f"[*] aged attach ok pid {pid}")
            return s, script, dev2
        except Exception as e:
            print(f"[!] aged attach failed: {str(e)[:90]}")
    fw.su("setenforce 1")
    return None, None, dev

def main():
    uid_m = re.search(r"userId=(\d+)", fw.sh("dumpsys package %s | grep userId" % PKG))
    uid = uid_m.group(1)
    print(f"[*] app uid = {uid}")

    # ---- PHASE A: identity + engagement (network on)
    gps = str(uuid.uuid4())
    ok = fw.set_gaid(gps)
    print(f"[*] fresh GAID: {gps} (set ok: {ok})")
    code, ref, hops, cURL = fw.fire_click(gps, "cline_tee1", None)
    print(f"[*] click: {code} reftag={ref}")

    # ---- PHASE B: wipe OFFLINE -> gated spawn -> app signs, cannot send
    fw.su("am force-stop %s" % fw.APP)
    fw.su("rm -f /data/data/%s/files/AdjustIoActivityState /data/data/%s/files/AdjustAttribution"
          % (fw.APP, fw.APP))
    block_app_net(True, uid)
    time.sleep(2)
    session, script, dev = attach_gated()
    if session is None:
        block_app_net(False, uid)
        sys.exit("no frida / gated spawn failed")
    time.sleep(6)
    fw.su("input keyevent KEYCODE_HOME"); time.sleep(3)
    fw.su("am start -n %s/.ui.main.MainActivity" % fw.APP)
    SIGPAIRS.wait(25); time.sleep(4)
    bk = cap.get("bykind", {})
    ses = bk.get("session") or {}
    pairs = ses.get("pairs") or (cap["sigpairs"][-1] if cap["sigpairs"] else None)
    own_blob = ses.get("blob") or (cap["nSign"][-1] if cap["nSign"] else None)
    own_hdr = auth_from_blob(own_blob) if own_blob else None
    print(f"[*] captured: pairs={pairs is not None} header={own_hdr is not None} blob={own_blob is not None}")
    if pairs is None or own_hdr is None or own_blob is None:
        try: session.detach()
        except Exception: pass
        block_app_net(False, uid)
        sys.exit("capture incomplete")
    pd = dict(pairs)
    print(f"[*] identity: gps={pd.get('gps_adid')} auid={pd.get('android_uuid')} kind={pd.get('activity_kind')}")

    # ---- PHASE C: mint attribution with the SAME live process (same key2, no re-attach)
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z+0530", time.gmtime(time.time() + 19800))
    apairs = []
    for k, v in pairs:
        if k in ("created_at", "sent_at"):
            apairs.append([k, now])
        elif k == "activity_kind":
            apairs.append([k, "attribution"])
        else:
            apairs.append([k, v])
    if not any(k == "adj_verification" for k, _ in apairs):
        apairs.append(["adj_verification", "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"])
    canon0 = cap["canonical"][-1] if cap["canonical"] else None
    if canon0:
        try:
            created0 = re.search(r"created_at=([^,}]+)", canon0).group(1)
            sent0 = re.search(r"sent_at=([^,}]+)", canon0).group(1)
            canon = canon0.replace("activity_kind=session", "activity_kind=attribution")
            canon = canon.replace(created0, now).replace(sent0, now)
            print(f"[canon] using REAL d3 canonical ({len(canon0)}B), mutated -> attribution")
        except Exception as e:
            print(f"[canon] real canonical unusable ({e}); building from pairs")
            canon = "{" + ", ".join(f"{k}={'null' if v is None else v}" for k, v in apairs) + "}"
    else:
        print("[canon] no d3 capture; building from pairs")
        canon = "{" + ", ".join(f"{k}={'null' if v is None else v}" for k, v in apairs) + "}"
    mint = script.exports_sync.mint3({"canonical": canon, "pairs": apairs})
    MINT.wait(20)
    print(f"[mint3] ok={mint.get('ok')} err={mint.get('error')} blobLen={mint.get('blobLen')}")
    if not mint.get("ok"):
        mr = cap.get("mint") or pull_mint_file()
        if mr and mr.get("ok"):
            mint = mr; print("[mint3] recovered via %s" % ("event" if cap.get("mint") else "file"))
    try:
        session.detach()
    except Exception:
        pass
    fw.su("am force-stop %s" % fw.APP); time.sleep(2)
    block_app_net(False, uid)
    print(f"[*] net unblocked (uid {uid})")
    if not mint.get("ok") or not mint.get("blobB64"):
        sys.exit("mint3 failed")

    # ---- PHASE D: send everything from Python
    time.sleep(3)
    s1 = send_pkg("https://app.adjust.com/session", pairs, own_blob, own_hdr, "POST")
    time.sleep(4)
    a1 = send_pkg("https://app.adjust.com/attribution", apairs, mint["blobB64"],
                  mint["header"], "GET")
    time.sleep(6)
    a2 = send_pkg("https://app.adjust.com/attribution", apairs, mint["blobB64"],
                  mint["header"], "GET")
    time.sleep(6)
    a3 = send_pkg("https://app.adjust.com/attribution", apairs, mint["blobB64"],
                  mint["header"], "GET")
    res = {"gps": gps, "click": {"code": code, "ref": ref},
           "session": {"st": s1[0], "body": s1[1][:400]},
           "attr_mint": {"st": a1[0], "body": a1[1][:400]},
           "attr_mint_replay": {"st": a2[0], "body": a2[1][:400]},
           "attr_mint_replay2": {"st": a3[0], "body": a3[1][:400]},
           "pairs_session": pairs, "pairs_attr": apairs}
    json.dump(res, open(OUT, "w"), indent=1)
    print(f"[*] saved {OUT}")
    both = a1[1] + a2[1] + a3[1]
    print("[VERDICT]", "NON-ORGANIC WIN" if "VKM" in both else
          ("Organic" if "Organic" in both else "?"))

if __name__ == "__main__":
    main()
