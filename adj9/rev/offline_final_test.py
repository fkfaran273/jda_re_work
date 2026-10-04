"""offline_final_test.py -- THE booking test through the OkHttp-fingerprint
transport, in two phases.

Background (http_fingerprint_diff.md, 2026-09-27): with the SAME claims and
the SAME adj9 blob, the app's /session books NON-ORGANIC and our Python
/session books ORGANIC.  The measured transport differences are the TLS
ClientHello (Conscrypt 517-B padded vs OpenSSL ML-KEM), header casing/order,
%20 vs '+' encoding, Connection/Accept-Encoding values, and connection
reuse.  okhttp_transport.py reproduces the app's fingerprint (measured:
517-B hello, 13/13 extensions, 16/17 ciphers, byte-exact header block).

Phase 1 -- genuine-blob replay probe (no device):
    POST /session with the captured genuine wire body
    (transport/fp_session_body.txt) + the captured genuine blob
    (transport_blob.txt) through the fingerprint-matched transport.
    GET  /attribution with the same blob.  Recognition signals (ask_in,
    non-Organic verdict, or a 400 reject that our mints never get) tell us
    the server verifies the blob through this transport.

Phase 2 -- FULLY OFFLINE booking (THE GOAL):
    fresh GAID (written into GMS on the device) -> Python click ->
    Python mint (F.py region, FinEx VM) -> Python /session + /sdk_click
    through the fingerprint-matched transport, one keep-alive connection,
    session first -> device oracle read (wipe app state, relaunch the real
    app, read its AdjustAttribution) -> Python /attribution poll last (the
    app's verdict is captured first because a crafted poll can downgrade a
    booked record).

Usage:  python offline_final_test.py [--skip-phase1] [--ctit 210]
Result: offline_final_result.json
"""
import base64
import json
import os
import re
import subprocess
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "adj9_tool"))

import okhttp_transport as OK
import mint_pipeline as M
import adj9_full_chain as F

SERIAL = "ZD2228MY3X"
PKG = "com.penti.app"
GMS = "com.google.android.gms"
XML = "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml"
ATTR_FILE = "/data/data/%s/files/AdjustAttribution" % PKG
STATE_FILE = "/data/data/%s/files/AdjustIoActivityState" % PKG
UUID_RE = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
RESULT = os.path.join(HERE, "offline_final_result.json")

TRACKER = "https://app.adjust.com/1sd1lk6a"
CLICK_UA = ("Mozilla/5.0 (Linux; Android 12; moto g 42) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36")

# The 43 source fields of the genuine /session wire body (SAZ order minus
# mcc/mnc -- no SIM on the g42 -- plus enqueue_size), i.e.
# clean_session_canon.txt with enqueue_size=0 appended.
SESSION_KEYS = [
    "store_name_from_system", "gps_adid_attempt", "api_level", "hardware_name",
    "app_version", "app_token", "installed_at", "created_at", "wait_total",
    "device_type", "language", "gps_adid", "foreground", "connectivity_type",
    "device_manufacturer", "display_width", "device_name",
    "needs_response_details", "os_build", "updated_at", "cpu_type",
    "retry_count", "screen_size", "screen_format", "last_error",
    "gps_adid_src", "wait_time", "os_version", "first_error", "android_uuid",
    "sent_at", "offline_mode_enabled", "environment", "screen_density",
    "attribution_deeplink", "session_count", "display_height", "package_name",
    "initiating_package_name", "os_name", "ui_mode", "enqueue_size",
    "tracking_enabled",
]

# The genuine /sdk_click wire body key order (SAZ 2_c.txt minus mcc/mnc).
CLICK_KEYS = [
    "api_level", "hardware_name", "app_version", "app_token", "installed_at",
    "device_type", "language", "gps_adid", "source", "foreground",
    "connectivity_type", "os_build", "click_time", "cpu_type",
    "install_version", "screen_size", "gps_adid_src", "subsession_count",
    "sent_at", "offline_mode_enabled", "screen_density", "session_count",
    "ui_mode", "gps_adid_attempt", "session_length", "created_at",
    "referrer_api", "device_manufacturer", "display_width", "time_spent",
    "device_name", "needs_response_details", "updated_at", "screen_format",
    "click_time_server", "os_version", "google_play_instant",
    "install_begin_time_server", "android_uuid", "referrer", "environment",
    "attribution_deeplink", "install_begin_time", "display_height",
    "package_name", "os_name", "tracking_enabled",
]

# The genuine /attribution query fields (SAZ 4_c / transport/attr_query.txt).
ATTR_KEYS = [
    "initiated_by", "gps_adid_attempt", "api_level", "app_version",
    "app_token", "os_version", "created_at", "device_type", "gps_adid",
    "foreground", "android_uuid", "sent_at", "offline_mode_enabled",
    "device_name", "environment", "needs_response_details",
    "attribution_deeplink", "package_name", "os_name", "ui_mode",
    "gps_adid_src", "tracking_enabled",
]

DEV = {  # the moto g42 device facts (clean_session_canon.txt)
    "store_name_from_system": "com.android.vending",
    "gps_adid_attempt": "1", "api_level": "31",
    "hardware_name": "S2SE32.28-28-4", "app_version": "3.14.0",
    "app_token": "jut9tib0eeps", "wait_total": "0.0", "device_type": "phone",
    "language": "tr", "foreground": "1", "connectivity_type": "1",
    "device_manufacturer": "motorola", "display_width": "1080",
    "device_name": "moto g42", "needs_response_details": "1",
    "os_build": "S2SE32.28-28-4", "cpu_type": "arm64-v8a",
    "retry_count": "0", "screen_size": "normal", "screen_format": "long",
    "last_error": "0", "gps_adid_src": "service", "wait_time": "0.0",
    "os_version": "12", "first_error": "0", "offline_mode_enabled": "0",
    "environment": "production", "screen_density": "high",
    "attribution_deeplink": "1", "display_height": "2237",
    "package_name": "com.penti.app",
    "initiating_package_name": "com.android.vending", "os_name": "android",
    "ui_mode": "1", "enqueue_size": "0", "tracking_enabled": "1",
    "install_version": "3.14.0",
}


def parse_canon():
    """clean_session_canon.txt -> ordered dict (canon order preserved)."""
    out = {}
    for k, v in re.findall(r"([a-z_0-9]+)=([^,\n]*)",
                           open(os.path.join(HERE, "clean_session_canon.txt"),
                                encoding="utf-8").read()):
        out[k] = v
    return out


# ---------------------------------------------------------------------------
# device helpers (root su, proven in offline_test.py / farm_win.py)
# ---------------------------------------------------------------------------
def adb(*a, t=120):
    r = subprocess.run(["adb", "-s", SERIAL] + list(a), capture_output=True,
                       timeout=t)
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def su(cmd, t=120):
    b = base64.b64encode(cmd.encode()).decode()
    inner = "echo %s | base64 -d | sh" % b
    b2 = base64.b64encode(inner.encode()).decode()
    return adb("shell", '/debug_ramdisk/su -c "echo %s | base64 -d | sh"' % b2,
               t=t)


def su_file(path):
    r = subprocess.run(["adb", "-s", SERIAL, "exec-out",
                        "/debug_ramdisk/su", "-c", "base64 %s" % path],
                       capture_output=True)
    try:
        return base64.b64decode(r.stdout)
    except Exception:
        return b""


def get_gaid():
    m = re.search(rb'name="adid_key">([^<]*)<',
                  su_file(XML).replace(b"\r", b""))
    if m:
        return m.group(1).decode()
    m = re.search(UUID_RE.encode(), su_file(XML).replace(b"\r", b""))
    return m.group(0).decode() if m else None


def set_gaid(new):
    cur = su_file(XML).replace(b"\r", b"")
    m = re.search(UUID_RE.encode(), cur)
    if not m:
        return None
    old = m.group(0).decode()
    su("echo %s | base64 -d > /data/local/tmp/adid_new.xml"
       % base64.b64encode(cur.replace(old.encode(), new.encode())).decode())
    su("cat /data/local/tmp/adid_new.xml > %s && am force-stop %s" % (XML, GMS))
    time.sleep(2)
    return old


def wipe_app_state():
    su("rm -f %s %s /data/data/%s/files/PackageQueue "
       "/data/data/%s/shared_prefs/adjust_preferences.xml"
       % (ATTR_FILE, STATE_FILE, PKG, PKG))
    su("am force-stop %s" % PKG)
    time.sleep(2)


def read_app_verdict():
    at = su_file(ATTR_FILE).decode("ascii", "replace")
    m = re.search(r"\{[^{}]*tracker_token[^{}]*\}", at)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# phase 1 -- genuine-blob replay through the matched transport
# ---------------------------------------------------------------------------
def phase1(res):
    print("=" * 72, flush=True)
    print("[phase1] genuine-blob replay via the OkHttp-fingerprint transport",
          flush=True)
    canon = parse_canon()
    blob_b64 = open(os.path.join(HERE, "transport_blob.txt")).read().strip()
    auth = OK.auth_header(blob_b64)
    body_path = os.path.join(HERE, "transport", "fp_session_body.txt")
    if os.path.exists(body_path):
        body = open(body_path, "rb").read()          # captured wire body
        src = "transport/fp_session_body.txt (captured)"
    else:
        canon["enqueue_size"] = "0"
        body = OK.okhttp_form_encode({k: canon[k] for k in SESSION_KEYS})
        src = "clean_session_canon.txt + enqueue_size (rebuilt)"
    t = OK.OkHttpTransport()
    out = {"body_source": src, "body_len": len(body)}
    try:
        st, resp = t.post_raw("/session", body, auth)
        out["session"] = {"status": st, "body": resp[:400]}
        print("[phase1] /session -> %s %s" % (st, resp[:200]), flush=True)

        # attribution read with the same blob + same connection
        sec = int(time.time())
        q = {k: DEV.get(k, canon.get(k, "")) for k in ATTR_KEYS}
        q.update({
            "initiated_by": "sdk",
            "gps_adid": canon["gps_adid"],
            "android_uuid": canon["android_uuid"],
            "created_at": F.fmt(sec, 666).decode(),
            "sent_at": F.fmt(sec, 696).decode(),
        })
        st2, resp2 = t.get("/attribution", q, auth)
        out["attribution"] = {"status": st2, "body": resp2[:600]}
        print("[phase1] /attribution -> %s %s" % (st2, resp2[:300]), flush=True)
        try:
            a = json.loads(resp2).get("attribution", {})
            out["verdict"] = {"tracker_token": a.get("tracker_token"),
                              "network": a.get("network"),
                              "engagement_time": a.get("engagement_time")}
        except Exception:
            out["verdict"] = None
    finally:
        t.close()

    resp1 = out.get("session", {}).get("body", "")
    try:
        j = json.loads(out["session"]["body"])
    except Exception:
        j = {}
    signals = []
    if "ask_in" in resp1:
        signals.append("ask_in=%s" % j.get("ask_in"))
    if out.get("verdict") and out["verdict"].get("network") \
            and out["verdict"]["network"] != "Organic":
        signals.append("non-Organic verdict %s" % out["verdict"]["network"])
    if out["session"]["status"] == 400:
        signals.append("400-reject: %s" % resp1[:160])
    out["recognition_signals"] = signals
    out["recognized"] = bool(signals)
    print("[phase1] signals: %s" % (signals or "none"), flush=True)
    res["phase1_blob_replay"] = out
    return out


# ---------------------------------------------------------------------------
# phase 2 -- fully offline booking
# ---------------------------------------------------------------------------
def phase2(res, ctit=210.0, creative="pyokhttp_t1"):
    print("=" * 72, flush=True)
    print("[phase2] FULLY OFFLINE booking via the matched transport", flush=True)
    out = {"ctit_s": ctit, "creative": creative}
    gps, auid = str(uuid.uuid4()), str(uuid.uuid4())
    out["gps_adid"] = gps
    out["android_uuid"] = auid
    print("[phase2] fresh gps=%s auid=%s" % (gps, auid), flush=True)

    # -- 1. fresh GAID into GMS -------------------------------------------
    old = set_gaid(gps)
    got = get_gaid()
    out["gaid_old"] = old
    out["gaid_readback"] = got
    print("[phase2] GAID %s -> %s (readback %s)" % (old, gps, got), flush=True)
    if got != gps:
        out["error"] = "GAID write failed"
        res["phase2_offline"] = out
        return out

    # -- 2. app must be dead and clean before booking ----------------------
    wipe_app_state()

    # -- 3. Python click (tracker redirect, PC egress) ----------------------
    from curl_cffi import requests as cr
    cs = cr.Session(impersonate="chrome131")
    url = (TRACKER + "?campaign=AH&adgroup=vkm_0926_36&creative=" + creative
           + "&click_id=" + gps + "&idfa=" + gps + "&gps_adid=" + gps)
    r = cs.get(url, headers={"User-Agent": CLICK_UA}, allow_redirects=False,
               timeout=30)
    referrer = None
    loc = r.headers.get("Location", "")
    if "referrer=" in loc:
        referrer = loc.split("referrer=", 1)[1]
    t_click = time.time()
    out["click"] = {"status": r.status_code,
                    "referrer": (referrer or "")[:200]}
    print("[phase2] click -> %s referrer=%s"
          % (r.status_code, (referrer or "(none)")[:80]), flush=True)

    # -- 4. wait the real CTIT (click -> install_begin = 210 s, win recipe) -
    target = t_click + ctit + 5
    while time.time() < target:
        time.sleep(5)
        print("[phase2]   CTIT wait... %3.0fs"
              % (time.time() - t_click), flush=True)

    # -- 5. Python mint + send, ONE keep-alive connection, session first ----
    t = OK.OkHttpTransport()
    try:
        sec = int(time.time())
        ins = F.fmt(t_click + 217, 431).decode()      # win recipe: +217.431 s

        s_params = {k: DEV[k] for k in SESSION_KEYS if k in DEV}
        s_params.update({"gps_adid": gps, "android_uuid": auid,
                         "session_count": "1",
                         "installed_at": ins, "updated_at": ins,
                         "created_at": F.fmt(sec - 1, 928).decode(),
                         "sent_at": F.fmt(sec - 1, 942).decode()})
        # the genuine signing map: wire fields + activity_kind + client_sdk +
        # adj_verification (capture_parsed.json canonical composition)
        sign_map = dict(s_params)
        sign_map.update({"activity_kind": "session",
                         "client_sdk": OK.CLIENT_SDK,
                         "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
                         "adj_signing_id": "1500000", "headers_id": "10",
                         "native_version": "5.0.0"})
        blob_s = M.mint_blob(sign_map, sec, kind="session")
        print("[phase2] session blob minted (%d B, sec=%d)"
              % (len(blob_s), sec), flush=True)
        st, resp = t.post("/session", s_params, OK.auth_header(
            base64.b64encode(blob_s).decode()))
        out["session"] = {"status": st, "body": resp[:400],
                          "second": sec, "blob_hex": blob_s.hex()}
        print("[phase2] /session -> %s %s" % (st, resp[:200]), flush=True)

        # -- 6. /sdk_click on the SAME connection (~1 s later, app order) ---
        time.sleep(1.0)
        sec2 = int(time.time())
        c_params = {k: DEV[k] for k in CLICK_KEYS if k in DEV}
        c_params.update({"gps_adid": gps, "android_uuid": auid,
                         "session_count": "1", "session_length": "0",
                         "time_spent": "0", "subsession_count": "1",
                         "google_play_instant": "0",
                         "source": "install_referrer",
                         "referrer_api": "google",
                         "installed_at": ins, "updated_at": ins,
                         "created_at": F.fmt(sec2, 961).decode(),
                         "sent_at": F.fmt(sec2, 970).decode(),
                         "click_time": F.fmt(t_click, 0).decode(),
                         "click_time_server": F.fmt(t_click + 1, 0).decode(),
                         "install_begin_time": F.fmt(t_click + 210, 0).decode(),
                         "install_begin_time_server":
                             F.fmt(t_click + 211, 0).decode(),
                         "referrer": referrer or "utm_source%3D%28not%2520set%29"
                                     "%26utm_medium%3D%28not%2520set%29"})
        sign_map2 = dict(c_params)
        sign_map2.update({"activity_kind": "click",
                          "client_sdk": OK.CLIENT_SDK,
                          "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
                          "adj_signing_id": "1500000", "headers_id": "10",
                          "native_version": "5.0.0"})
        blob_c = M.mint_blob(sign_map2, sec2, kind="click")
        stc, respc = t.post("/sdk_click", c_params, OK.auth_header(
            base64.b64encode(blob_c).decode()))
        out["sdk_click"] = {"status": stc, "body": respc[:400],
                            "second": sec2, "blob_hex": blob_c.hex()}
        print("[phase2] /sdk_click -> %s %s" % (stc, respc[:200]), flush=True)

        # -- 7. device oracle FIRST (a crafted poll can downgrade a record) -
        wipe_app_state()
        su("am start -n %s/.ui.main.MainActivity" % PKG)
        print("[phase2] app relaunched, waiting for the oracle verdict...",
              flush=True)
        verdict = None
        for i in range(12):                      # up to ~120 s
            time.sleep(10)
            verdict = read_app_verdict()
            if verdict:
                break
            print("[phase2]   oracle... %ds" % ((i + 1) * 10), flush=True)
        out["app_verdict"] = verdict
        non_organic = bool(verdict) and verdict.get("network") \
            and verdict["network"] != "Organic"
        print("[phase2] APP VERDICT: %s" % json.dumps(verdict), flush=True)
        print("[phase2] => %s" % ("NON-ORGANIC — THE GOAL"
                                  if non_organic else
                                  (verdict or {}).get("network", "no verdict"),
                                  ), flush=True)

        # -- 8. Python /attribution poll LAST (secondary read) --------------
        sec3 = int(time.time())
        a_params = {k: DEV[k] for k in ATTR_KEYS if k in DEV}
        a_params.update({"initiated_by": "sdk", "gps_adid": gps,
                         "android_uuid": auid,
                         "created_at": F.fmt(sec3, 666).decode(),
                         "sent_at": F.fmt(sec3, 696).decode()})
        sign_map3 = dict(a_params)
        sign_map3.update({"activity_kind": "attribution",
                          "client_sdk": OK.CLIENT_SDK,
                          "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
                          "adj_signing_id": "1500000", "headers_id": "10",
                          "native_version": "5.0.0"})
        blob_a = M.mint_blob(sign_map3, sec3, kind="attribution")
        sta, respa = t.get("/attribution", a_params, OK.auth_header(
            base64.b64encode(blob_a).decode()))
        out["python_attribution"] = {"status": sta, "body": respa[:600]}
        print("[phase2] /attribution (python) -> %s %s"
              % (sta, respa[:300]), flush=True)
        out["verdict"] = ("NON-ORGANIC" if non_organic else
                          (verdict or {}).get("network") or "NO_VERDICT")
    finally:
        t.close()

    # -- 9. leave the device as we found it ---------------------------------
    if old:
        set_gaid(old)
        print("[phase2] GAID restored to %s" % old, flush=True)
    res["phase2_offline"] = out
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-phase1", action="store_true")
    ap.add_argument("--ctit", type=float, default=210.0)
    ap.add_argument("--creative", default="pyokhttp_t1")
    args = ap.parse_args()

    res = {"date": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "transport": "okhttp_transport.OkHttpTransport "
                        "(tls_client okhttp4_android_12, force_http1, "
                        "OkHttp header order, %20 FormBody encoding)",
           "fingerprint": {"tls_hello": "517B padded Conscrypt, 13/13 exts, "
                                        "16/17 ciphers (0xc00a missing), "
                                        "3/3 groups, 9/9 sigalgs, ALPN "
                                        "http/1.1 only",
                           "headers": "byte-exact OkHttp order/casing"}}
    if not args.skip_phase1:
        phase1(res)
        json.dump(res, open(RESULT, "w"), indent=1)
    phase2(res, ctit=args.ctit, creative=args.creative)
    json.dump(res, open(RESULT, "w"), indent=1)
    print("=" * 72)
    v = (res.get("phase2_offline") or {}).get("verdict")
    print("FINAL VERDICT: %s" % v)
    print("saved", RESULT)


if __name__ == "__main__":
    main()
