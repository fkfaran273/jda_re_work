"""oracle_ab.py -- decisive A/B: does the server accept an ORACLE-signed request?

Same flow as oneclick.py, but instead of the Python reimplementation minting
the adj9 envelope, we hand the three exact wire maps to the on-device LSPosed
oracle (adj9oracle) which signs them with the app's REAL TEE-bound signer and
returns the Authorization headers.  We then send session/sdk_click/attribution
with those oracle-signed headers.

Arms:
  --arm oracle  : Authorization from the device signer (expected NON-ORGANIC)
  --arm python  : Authorization from adj9_signer (expected ORGANIC, control)
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
from urllib.error import HTTPError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_api as A
import adj9_signer as S

SERIAL = "ZD2228MY3X"
LINK = ("https://app.adjust.com/1sd1lk6a?campaign=AH"
        "&adgroup=vkm_0926_36&creative=cline_1p8t3"
        "&click_id={click_id}&gps_adid={click_id}")
CTIT = 8.0
CTIT_BEGIN = 6.0
REFERRER = "utm_source=google-play&utm_medium=organic"
SIGN_IN = "/data/local/tmp/adj9_sign_in"
SIGN_OUT = "/data/local/tmp/adj9_sign_out"
APP_PKG = "com.penti.app"


def sh(cmd, timeout=60):
    r = subprocess.run(["adb", "-s", SERIAL, "shell", "su", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout)
    return r.stdout


def sh_raw(cmd, timeout=60):
    r = subprocess.run(["adb", "-s", SERIAL, "shell", cmd],
                       capture_output=True, text=True, timeout=timeout)
    return r.stdout


def build_maps(api, gps, auid, t_click):
    """Exact wire maps for /session, /sdk_click, /attribution."""
    sec_install = int(t_click) + int(CTIT)
    ins = api.fmt(sec_install, 431).decode()
    tb = t_click + CTIT_BEGIN

    sp = api._base("S1P")
    sp.update({"gps_adid": gps, "android_uuid": auid,
               "created_at": api.fmt(sec_install - 1, 928).decode(),
               "sent_at": api.fmt(sec_install - 1, 942).decode(),
               "installed_at": ins, "updated_at": ins})

    cp = api._base("S2P")
    cp.update({"gps_adid": gps, "android_uuid": auid,
               "created_at": api.fmt(sec_install - 1, 961).decode(),
               "sent_at": api.fmt(sec_install - 1, 970).decode(),
               "installed_at": ins, "updated_at": ins,
               "referrer": REFERRER, "source": "install_referrer",
               "referrer_api": "google",
               "click_time": api.fmt(t_click, 0).decode(),
               "click_time_server": api.fmt(t_click - 2, 0).decode(),
               "install_begin_time": api.fmt(tb, 0).decode(),
               "install_begin_time_server": api.fmt(tb - 2, 0).decode()})

    d = api._dev_fields()
    sec_attr = sec_install
    ap = {"initiated_by": "backend", "gps_adid_attempt": "1",
          "api_level": d["api_level"], "app_version": d["app_version"],
          "app_token": A.APP_TOKEN, "os_version": d["os_version"],
          "created_at": api.fmt(sec_attr - 1, 666).decode(),
          "device_type": "phone", "gps_adid": gps, "foreground": "1",
          "android_uuid": auid,
          "sent_at": api.fmt(sec_attr - 1, 696).decode(),
          "offline_mode_enabled": "0", "device_name": d["device_name"],
          "environment": "production", "needs_response_details": "1",
          "attribution_deeplink": "1", "package_name": APP_PKG,
          "os_name": "android", "ui_mode": "1", "gps_adid_src": "service",
          "tracking_enabled": "1"}
    if api.ADD_IDFA:
        ap["idfa"] = gps
    return [("session", sp), ("click", cp), ("attribution", ap)]


def to_control(maps):
    out = []
    for kind, m in maps:
        out.append("TASK")
        out.append("KIND=" + kind)
        out.append("SDK=" + S.CLIENT_SDK)
        for k, v in m.items():
            out.append(str(k) + "\x01" + str(v))
    return "\n".join(out) + "\n"


def sign_on_device(maps, n):
    """Push control file, make the app sign, return list of n auth headers."""
    ctrl = to_control(maps)
    local = os.path.join(HERE, "_ctrl.tmp")
    with open(local, "w", encoding="utf-8", newline="") as f:
        f.write(ctrl)
    subprocess.run(["adb", "-s", SERIAL, "push", local, SIGN_IN],
                   capture_output=True, text=True)
    sh("chmod 666 %s; : > %s; chmod 666 %s" % (SIGN_IN, SIGN_OUT, SIGN_OUT))
    # force a fresh app session so the oracle fires
    sh("am force-stop %s" % APP_PKG)
    sh("rm -f /data/data/%s/files/AdjustIoActivityState" % APP_PKG)
    time.sleep(1)
    sh_raw("monkey -p %s -c android.intent.category.LAUNCHER 1" % APP_PKG)
    # poll for n AUTH lines
    deadline = time.time() + 60
    auths = []
    while time.time() < deadline:
        out = sh("cat %s" % SIGN_OUT)
        auths = []
        for line in out.splitlines():
            m = re.match(r"AUTH\s+(\d+)\s+(\S+.*)$", line.strip())
            if m:
                auths.append((int(m.group(1)), m.group(2)))
        auths.sort()
        if len(auths) >= n:
            return [a for _, a in auths[:n]]
        time.sleep(2)
    return [a for _, a in auths]


def send_raw(api, path, params, auth, method="POST"):
    url = A.BASE_URL + path
    headers = {"Client-SDK": S.CLIENT_SDK, "User-Agent": api.UA,
               "Authorization": auth}
    if method == "POST":
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method="POST")
    else:
        full = url + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(full, headers=headers, method="GET")
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return r.getcode(), r.read().decode("utf-8", "replace")
    except HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return "ERR", str(e)


def fire_click(gps):
    url = LINK.replace("{click_id}", gps)
    t = time.time()
    try:
        r = urllib.request.urlopen(url, timeout=45)
        code = r.getcode()
    except HTTPError as e:
        code = e.code
    except Exception as e:
        code = "ERR:%s" % e
    print("  click HTTP %s" % code)
    return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", choices=["oracle", "python"], default="oracle")
    args = ap.parse_args()

    api = A.Api(transport="pc")
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    print("=" * 62)
    print(" ORACLE A/B -- arm=%s" % args.arm)
    print(" gps_adid=%s" % gps)
    print("=" * 62)

    print("\nSTEP 1  firing genuine click")
    t_click = fire_click(gps)

    maps = build_maps(api, gps, auid, t_click)
    print("  built maps: %s" % ", ".join("%s(%d)" % (k, len(m)) for k, m in maps))

    if args.arm == "oracle":
        print("\nSTEP 2  signing on device (oracle)")
        auths = sign_on_device(maps, 3)
        if len(auths) < 3:
            print("  ORACLE FAILED: got %d/3 auth headers" % len(auths))
            for a in auths:
                print("   ", a[:100])
            return 2
        for i, a in enumerate(auths):
            print("  auth[%d] %d chars  sig=%s..."
                  % (i, len(a), re.search(r'signature="([^"]+)"', a).group(1)[:32]))
    else:
        print("\nSTEP 2  signing in python (control arm)")
        auths = []
        for kind, m in maps:
            val = S.claims_from_wire(m, kind)
            blob, _ = S.mint_blob(val, kind)
            auths.append(S.auth_header(blob))
            print("  %s blob=%dB" % (kind, len(blob)))

    # wait out CTIT
    wait = (int(t_click) + int(CTIT)) - time.time()
    if wait > 0:
        print("\n  waiting %.0fs for CTIT..." % wait)
        time.sleep(wait)

    print("\nSTEP 3  sending install (session + sdk_click)")
    c, b = send_raw(api, "/session", maps[0][1], auths[0])
    print("  /session   -> %s %s" % (c, b[:120]))
    c, b = send_raw(api, "/sdk_click", maps[1][1], auths[1])
    print("  /sdk_click -> %s %s" % (c, b[:120]))

    print("\nSTEP 4  polling attribution")
    verdict = None
    for i in range(5):
        time.sleep(1 if i == 0 else 12)
        c, b = send_raw(api, "/attribution", maps[2][1], auths[2], method="GET")
        v = A.read_verdict(b)
        if v:
            verdict = v
            print("  poll %d %s token=%s eng=%s => %s"
                  % (i + 1, c, v["token"], v["engagement_time"], v["verdict"]))
            if not v["organic"]:
                break
        else:
            print("  poll %d %s (no verdict) %s" % (i + 1, c, b[:120]))

    print("\n" + "=" * 62)
    print(" ARM=%s  VERDICT: %s"
          % (args.arm, verdict["verdict"] if verdict else "NO VERDICT"))
    print("=" * 62)
    with open(os.path.join(HERE, "oracle_ab_%s.json" % args.arm), "w") as f:
        json.dump({"arm": args.arm, "gps_adid": gps, "verdict": verdict}, f,
                  indent=1)


if __name__ == "__main__":
    main()
