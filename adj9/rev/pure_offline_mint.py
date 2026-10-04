"""pure_offline_mint.py — THE COMPLETE TOOL.

Pipeline: fresh GAID → Python click → app launches (module captures S + claims
+ substitutes our blob) → Python reads the verdict.

The device's ONLY role: run the app for ~5 seconds while the LSPosed module
(1) captures the signing inputs, (2) blocks for our blob, (3) substitutes it.
Every signature byte is computed by this script.
"""
import base64, json, os, re, subprocess, sys, time, uuid, calendar

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mint_pipeline as M
import adj9_full_chain as F

SER = "ZD2228MY3X"
PKG = "com.penti.app"
FDIR = "/data/data/com.penti.app/files"
CTX = "u:object_r:app_data_file:s0:c146,c257,c512,c768"
MINTMODE = FDIR + "/adj9_mintmode"
MINT_REQ = FDIR + "/adj9_mint_req"
MINT_RESP = FDIR + "/adj9_mint_resp"
OUT = os.path.join(HERE, "pure_offline_result.json")

sys.stdout.reconfigure(line_buffering=True)


def adb(*a, t=90):
    r = subprocess.run(["adb", "-s", SER] + list(a), capture_output=True, timeout=t)
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def su(cmd):
    b = base64.b64encode(cmd.encode()).decode()
    inner = "echo %s | base64 -d | sh" % b
    b2 = base64.b64encode(inner.encode()).decode()
    return adb("shell", '/debug_ramdisk/su -c "echo %s | base64 -d | sh"' % b2)


def set_gaid(new):
    import base64 as B
    XML = "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml"
    r = subprocess.run(["adb", "-s", SER, "exec-out",
                        "/debug_ramdisk/su", "-c", "base64 " + XML], capture_output=True)
    cur = B.b64decode(r.stdout).decode('utf-8', 'replace')
    m = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", cur)
    if not m:
        return None
    old = m.group(0)
    patched = cur.replace(old, new)
    open('adid_tmp.bin', 'wb').write(patched.encode())
    subprocess.run(["adb", "-s", SER, "push", "adid_tmp.bin",
                    "/data/local/tmp/adid_tmp.bin"], capture_output=True)
    su("cp /data/local/tmp/adid_tmp.bin %s && am force-stop com.google.android.gms" % XML)
    return old


def main():
    # ===== SETUP =====
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    print("=" * 60)
    print("PURE OFFLINE MINT — fully script-computed signature")
    print("=" * 60)
    print("[1] fresh gps=%s" % gps, flush=True)

    subprocess.run(["adb", "-s", SER, "shell", "am", "force-stop", PKG], capture_output=True)
    time.sleep(1)
    old = set_gaid(gps)
    print("    GAID: %s -> %s" % (old, gps), flush=True)
    time.sleep(2)

    # ===== CLICK =====
    print("[2] firing click via curl_cffi...", flush=True)
    from curl_cffi import requests as cr
    s = cr.Session(impersonate="chrome131")
    chrome_ua = ("Mozilla/5.0 (Linux; Android 12; moto g 42) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36")
    click_url = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
                 "&creative=penti_generic&click_id=" + gps + "&idfa=" + gps + "&gps_adid=" + gps)
    r = s.get(click_url, headers={"User-Agent": chrome_ua},
              allow_redirects=False, timeout=30)
    print("    click: %d" % r.status_code, flush=True)
    t_click = time.time()

    # ===== WIPE + SET MINT MODE =====
    su("am force-stop %s" % PKG)
    su("rm -rf /data/data/%s/files /data/data/%s/shared_prefs /data/data/%s/databases" % (PKG, PKG, PKG))
    su("rm -f %s/adj9_mint_req %s/adj9_mint_resp" % (FDIR, FDIR))
    su("touch %s/adj9_mintmode" % FDIR)
    su("chcon %s %s/adj9_mintmode" % (CTX, FDIR))
    su("chmod 666 %s/adj9_mintmode" % FDIR)
    time.sleep(1)
    subprocess.run(["adb", "-s", SER, "logcat", "-c"], capture_output=True)

    # ===== LAUNCH =====
    adb("shell", "am", "start", "-n", "%s/.ui.main.MainActivity" % PKG)
    print("[3] app launched with mint mode ON; waiting for signing...", flush=True)

    # ===== POLL FOR MINT_REQ =====
    req = None
    req_path = FDIR + "/adj9_mint_req"
    for i in range(60):
        time.sleep(2)
        r = subprocess.run(["adb", "-s", SER, "exec-out",
                            "/debug_ramdisk/su", "-c", "base64 " + req_path],
                           capture_output=True, timeout=30)
        import base64 as B
        try:
            raw = B.b64decode(r.stdout).decode('utf-8', 'replace')
        except Exception:
            continue
        if raw.strip():
            req = raw
            print("[4] mint_req captured (len=%d) at t=%ds" % (len(req), i * 2), flush=True)
            break

    if not req:
        print("    FAIL: no mint_req", flush=True)
        su("rm -f %s/adj9_mintmode" % FDIR)
        return

    # ===== PARSE CLAIMS =====
    claims = {}
    for k, v in re.findall(r'([a-z_0-9]+)=([^,}\n]*)', req):
        claims.setdefault(k, v)
    kind_m = re.search(r'activity_kind=(\w+)', req)
    kind = kind_m.group(1) if kind_m else 'session'
    ca = re.search(r'(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)', req)
    second = calendar.timegm(tuple(int(ca.group(i)) for i in range(1, 6)) + (0,)) if ca else int(time.time())
    gps_ok = claims.get('gps_adid', '') == gps
    print("[5] claims captured: kind=%s second=%d gps_match=%s" % (kind, second, gps_ok), flush=True)

    # ===== MINT =====
    claims.setdefault('adj_signing_id', '1500000')
    claims.setdefault('headers_id', '10')
    claims.setdefault('native_version', '5.0.0')
    print("[6] minting blob (pure Python: F.py region + FinEx)...", flush=True)
    t0 = time.time()
    blob = M.mint_blob(claims, second, kind=kind)
    print("    minted %d B in %.0f s" % (len(blob), time.time() - t0), flush=True)

    # ===== DELIVER =====
    su("rm -f %s/adj9_mint_resp" % FDIR)
    h = blob.hex()
    open('mint_resp_hex.txt', 'w').write(h)
    subprocess.run(["adb", "-s", SER, "push", "mint_resp_hex.txt",
                    "/data/local/tmp/mint_resp_hex.txt"], capture_output=True)
    su("cp /data/local/tmp/mint_resp_hex.txt %s/adj9_mint_resp" % FDIR)
    su("chmod 666 %s/adj9_mint_resp" % FDIR)
    print("[7] blob delivered; the app will substitute and transmit...", flush=True)

    # ===== READ VERDICT =====
    verdict = None
    for i in range(15):
        time.sleep(12)
        raw = su("cat %s/AdjustAttribution 2>/dev/null" % FDIR)
        mm = re.search(r'\{"tracker_token[^}]*\}', raw.replace("\x00", ""))
        if mm:
            try:
                verdict = json.loads(mm.group(0))
            except Exception:
                pass
            if verdict:
                break

    # ===== RESULT =====
    print("[8] VERDICT:", json.dumps(verdict, indent=2) if verdict else "null", flush=True)
    net = verdict.get('network', '?') if verdict else '?'
    print("=" * 60)
    if net != 'Organic':
        print("*** NON-ORGANIC FROM SCRIPT-MINTED SIGNATURE ***")
        print("*** network=%s tracker=%s ***" % (net, verdict.get('tracker_token', '?')))
        print("*** GOAL ACHIEVED ***")
    else:
        print("*** Organic — the blob was not recognized ***")
    print("=" * 60)

    su("rm -f %s/adj9_mintmode" % FDIR)
    # restore device GAID
    if old:
        set_gaid(old)
    json.dump({"gps": gps, "auid": auid, "kind": kind, "second": second,
               "verdict": verdict, "minted_blob_hex": blob.hex()},
              open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()
