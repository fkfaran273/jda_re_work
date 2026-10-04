"""Full attribution flow where EVERY request is signed by the REAL device
libsigner (via frida), using a real click + genuine adjust_reftag referrer.

This is the decisive A/B against the Python-signed flow (click_referrer_test.py),
which produced ORGANIC with identical params/GAID/referrer. If THIS goes
NON-ORGANIC, the signature is the gate and the real libsigner (TEE key2) carries
something the Python reimplementation cannot.

The device signer mints all needed signatures in ONE frida session (the app's
anti-frida kills the process seconds after attach, so we mint fast, then send
from Python).
"""
import base64
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from urllib.error import HTTPError
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.join(HERE, "..", "rev", "agent")
BUNDLE = os.path.join(AGENT_DIR, "mintcl.js")
sys.path.insert(0, HERE)
import adj9_api as A          # noqa: E402  (for _base/_dev_fields/fmt/read_verdict)

LINK = ("https://app.adjust.com/1sd1lk6a?campaign=AH"
        "&adgroup=vkm_0926_36&creative=cline_1p8t3"
        "&click_id={click_id}&gps_adid={click_id}")
SERIAL = "ZD2228MY3X"
PKG = "com.penti.app"
CTIT = 4.0


def sh(*args):
    return subprocess.run(list(args), capture_output=True, text=True,
                          env={**os.environ, "MSYS_NO_PATHCONV": "1"})


def app_pid():
    p = sh("adb", "-s", SERIAL, "shell", "su -c 'ps -A | grep com.penti.app'")
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
    return None


def prep_device():
    """frida-server up, app freshly started, port forwarded. Returns app pid."""
    sh("adb", "-s", SERIAL, "shell",
       "su -c 'pkill -9 frida-server; pkill -9 com.penti.app; sleep 1; "
       "setsid /data/local/tmp/frida-server >/dev/null 2>&1 </dev/null &'")
    time.sleep(2)
    sh("adb", "-s", SERIAL, "forward", "tcp:27042", "tcp:27042")
    sh("adb", "-s", SERIAL, "shell", f"am start -n {PKG}/.ui.main.MainActivity")
    for _ in range(12):
        time.sleep(1)
        pid = app_pid()
        if pid:
            return pid
    return None


def mint_all(param_sets):
    """param_sets: list of {'activity':..., 'globals':...}. Returns list of
    authorization header strings (or None on failure), minted in ONE session."""
    import frida
    pid = prep_device()
    if not pid:
        return [None] * len(param_sets)
    print("  attached to app pid", pid)
    dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    sess = dev.attach(pid)
    with open(BUNDLE, encoding="utf-8") as f:
        sc = sess.create_script(f.read())
    sc.load()
    time.sleep(1.5)
    out = []
    try:
        for ps in param_sets:
            r = sc.exports_sync.mint({"activity": ps["activity"],
                                      "globals": ps["globals"]})
            if r.get("ok") and r.get("authorization"):
                out.append(r["authorization"])
            else:
                print("   mint failed:", (r.get("error") or "")[:120])
                out.append(None)
    except Exception as e:
        print("   mint exc:", e)
        out = [None] * len(param_sets)
    try:
        sess.detach()
    except Exception:
        pass
    return out


def send_signed(path, params, auth, method="POST"):
    url = A.BASE_URL + path
    headers = {"Authorization": auth, "User-Agent": PKG}
    if method == "POST":
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
    else:
        full = url + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(full, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return "ERR", str(e)


def fire_click():
    cid = str(uuid.uuid4())
    url = LINK.replace("{click_id}", cid)
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent",
                   "Dalvik/2.1.0 (Linux; U; Android 12; moto g42)")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    op = urllib.request.build_opener(NoRedirect)
    t = time.time()
    try:
        r = op.open(req, timeout=45)
        loc = dict(r.getheaders()).get("location", "")
    except HTTPError as e:
        loc = dict(e.headers).get("location", "")
    ref = parse_qs(urlparse(loc).query).get("referrer", [""])[0]
    return cid, ref, t


def main():
    print("=" * 62)
    print(" adj9 REAL-DEVICE-SIGNED flow (frida libsigner) + real click referrer")
    print("=" * 62)
    api = A.Api(transport="pc")
    gps, ref, t_click = fire_click()
    print("  gps_adid :", gps)
    print("  referrer :", ref[:100])
    auid = str(uuid.uuid4())
    sec = int(t_click) + int(CTIT)
    ins = api.fmt(sec, 431).decode()
    tb = t_click + 2.0

    d = api._dev_fields()
    # Build the three wire param sets, then have the DEVICE sign each.
    sp = api._base("S1P")
    sp.update({"gps_adid": gps, "android_uuid": auid,
               "created_at": api.fmt(sec - 1, 928).decode(),
               "sent_at": api.fmt(sec - 1, 942).decode(),
               "installed_at": ins, "updated_at": ins})

    cp = api._base("S2P")
    cp.update({"gps_adid": gps, "android_uuid": auid,
               "created_at": api.fmt(sec - 1, 961).decode(),
               "sent_at": api.fmt(sec - 1, 970).decode(),
               "installed_at": ins, "updated_at": ins,
               "referrer": ref, "source": "install_referrer",
               "referrer_api": "google",
               "click_time": api.fmt(int(t_click), 0).decode(),
               "click_time_server": api.fmt(int(t_click) - 2, 0).decode(),
               "install_begin_time": api.fmt(int(tb), 0).decode(),
               "install_begin_time_server": api.fmt(int(tb) - 2, 0).decode()})

    ap = {"initiated_by": "backend", "gps_adid_attempt": "1",
          "api_level": d["api_level"], "app_version": d["app_version"],
          "app_token": A.APP_TOKEN, "os_version": d["os_version"],
          "created_at": api.fmt(sec - 1, 666).decode(),
          "device_type": "phone", "gps_adid": gps, "foreground": "1",
          "android_uuid": auid, "sent_at": api.fmt(sec - 1, 696).decode(),
          "offline_mode_enabled": "0", "device_name": d["device_name"],
          "environment": "production", "needs_response_details": "1",
          "attribution_deeplink": "1", "package_name": PKG,
          "os_name": "android", "ui_mode": "1", "gps_adid_src": "service",
          "tracking_enabled": "1"}

    G = {"activity_kind": "session", "client_sdk": A.S.CLIENT_SDK}
    Gc = {"activity_kind": "click", "client_sdk": A.S.CLIENT_SDK}
    Ga = {"activity_kind": "attribution", "client_sdk": A.S.CLIENT_SDK}

    # The real Signer builds its signed map from the activity map PLUS these
    # fixed fields (present in the captured real activity map). They feed the
    # canonical; the wire carries them in the Authorization header instead.
    def mintmap(wire, kind):
        m = dict(wire)
        m.update({"activity_kind": kind, "client_sdk": A.S.CLIENT_SDK,
                  "adj_signing_id": A.S.ADJ_SIGNING_ID, "headers_id": "10",
                  "native_version": A.S.NATIVE_VERSION})
        return m

    print("\nMINTING on device (session, click, attribution)...")
    auths = mint_all([
        {"activity": mintmap(sp, "session"), "globals": G},
        {"activity": mintmap(cp, "click"), "globals": Gc},
        {"activity": mintmap(ap, "attribution"), "globals": Ga},
    ])
    for name, a in zip(("session", "click", "attribution"), auths):
        print("  %s sig: %s" % (name, "OK" if a else "NONE"))
    if not all(auths):
        print("could not mint all signatures; aborting")
        return 1

    print("\nSENDING (device-signed)...")
    code, body = send_signed("/session", sp, auths[0])
    print("  /session   -> %s %s" % (code, body[:90]))
    code, body = send_signed("/sdk_click", cp, auths[1])
    print("  /sdk_click -> %s %s" % (code, body[:90]))

    print("\nPOLLING attribution (device-signed)...")
    verdict = None
    for i in range(5):
        time.sleep(1 if i == 0 else 12)
        code, body = send_signed("/attribution", ap, auths[2], method="GET")
        v = A.read_verdict(body)
        if v:
            verdict = v
            print("  poll %d/5 %s token=%s network=%s eng=%s => %s"
                  % (i + 1, code, v["token"], v["network"],
                     v["engagement_time"], v["verdict"]))
            if not v["organic"]:
                break
        else:
            print("  poll %d/5 %s (no verdict) %s" % (i + 1, code, body[:80]))
    print("\n" + "=" * 62)
    print(" VERDICT: %s" % (verdict["verdict"] if verdict else "NO VERDICT"))
    print("=" * 62)
    with open(os.path.join(HERE, "real_sig_last_run.json"), "w") as f:
        json.dump({"gps_adid": gps, "referrer": ref, "verdict": verdict}, f, indent=1)


if __name__ == "__main__":
    main()
