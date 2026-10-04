"""oracle_ab2.py -- corrected A/B: proper device-free signer vs device oracle.

The FIRST A/B (oracle_ab.py) python arm was mis-minted: it called
S.mint_blob(val, kind) with NO second and NO V, so the 16-byte header was
stamped with the *mint-time* second and the region was built from an unrelated
wall-clock V.  Per adj9_signer's own make_V docstring that is a "detectable
tell" -- the transmitted created_at/sent_at and the region seed must name the
same second.

This driver mints the python arm through the SAME properly-aligned path the
research API uses (adj9_api._sign / _V_for): second = the request second with
MINT_SKEW, V = make_V_in_window(created_ms, sent_ms, sec), pid = DEFAULT_PID.
Everything else (fresh GAID, genuine click, maps, transport) is identical to the
oracle arm, so the ONLY variable is again the signer.

Arms:
  --arm oracle : Authorization from the on-device LSPosed oracle (control win)
  --arm python : Authorization from adj9_api's aligned signer (the real test)
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
    return subprocess.run(["adb", "-s", SERIAL, "shell", "su", "-c", cmd],
                          capture_output=True, text=True, timeout=timeout).stdout


def sh_raw(cmd, timeout=60):
    return subprocess.run(["adb", "-s", SERIAL, "shell", cmd],
                          capture_output=True, text=True, timeout=timeout).stdout


def build_maps(api, gps, auid, t_click):
    """Exact wire maps, identical to oracle_ab.py so both arms share the flow."""
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
    ap = {"initiated_by": "backend", "gps_adid_attempt": "1",
          "api_level": d["api_level"], "app_version": d["app_version"],
          "app_token": A.APP_TOKEN, "os_version": d["os_version"],
          "created_at": api.fmt(sec_install - 1, 666).decode(),
          "device_type": "phone", "gps_adid": gps, "foreground": "1",
          "android_uuid": auid,
          "sent_at": api.fmt(sec_install - 1, 696).decode(),
          "offline_mode_enabled": "0", "device_name": d["device_name"],
          "environment": "production", "needs_response_details": "1",
          "attribution_deeplink": "1", "package_name": APP_PKG,
          "os_name": "android", "ui_mode": "1", "gps_adid_src": "service",
          "tracking_enabled": "1"}
    if api.ADD_IDFA:
        ap["idfa"] = gps
    return [("session", sp), ("click", cp), ("attribution", ap)], sec_install, ins


def to_control(maps):
    out = []
    for kind, m in maps:
        out.append("TASK"); out.append("KIND=" + kind)
        out.append("SDK=" + S.CLIENT_SDK)
        for k, v in m.items():
            out.append(str(k) + "\x01" + str(v))
    return "\n".join(out) + "\n"


def sign_on_device(maps, n):
    ctrl = to_control(maps)
    local = os.path.join(HERE, "_ctrl2.tmp")
    open(local, "w", encoding="utf-8", newline="").write(ctrl)
    subprocess.run(["adb", "-s", SERIAL, "push", local, SIGN_IN],
                   capture_output=True, text=True)
    sh("chmod 666 %s; : > %s; chmod 666 %s" % (SIGN_IN, SIGN_OUT, SIGN_OUT))
    sh("am force-stop %s" % APP_PKG)
    sh("rm -f /data/data/%s/files/AdjustIoActivityState" % APP_PKG)
    time.sleep(1)
    sh_raw("monkey -p %s -c android.intent.category.LAUNCHER 1" % APP_PKG)
    deadline = time.time() + 60
    auths = []
    while time.time() < deadline:
        auths = []
        for line in sh("cat %s" % SIGN_OUT).splitlines():
            m = re.match(r"AUTH\s+(\d+)\s+(\S+.*)$", line.strip())
            if m:
                auths.append((int(m.group(1)), m.group(2)))
        auths.sort()
        if len(auths) >= n:
            return [a for _, a in auths[:n]]
        time.sleep(2)
    return [a for _, a in auths]


def mint_python(api, maps, sec_install):
    """Mint with PROPER alignment: second = sec_install, V from the ms window."""
    auths = []
    for kind, m in maps:
        val = S.claims_from_wire(m, kind)
        # the transmitted created_at/sent_at live in second (sec_install - 1)
        sec = sec_install
        c_ms = int(m["created_at"][20:23])
        s_ms = int(m["sent_at"][20:23])
        V = S.make_V_in_window(c_ms, s_ms, sec=sec - 1)
        blob, info = S.mint_blob(val, kind, second=sec, V=V, pid=S.DEFAULT_PID)
        auths.append(S.auth_header(blob))
        print("  %s blob=%dB second=%s V=%08x status=%s"
              % (kind, len(blob), sec, V, info["status"]))
    return auths


def send_raw(api, path, params, auth, method="POST"):
    url = A.BASE_URL + path
    headers = {"Client-SDK": S.CLIENT_SDK, "User-Agent": api.UA,
               "Authorization": auth}
    if method == "POST":
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=urllib.parse.urlencode(params).encode(),
                                     headers=headers, method="POST")
    else:
        req = urllib.request.Request(url + "?" + urllib.parse.urlencode(params),
                                     headers=headers, method="GET")
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
        r = urllib.request.urlopen(url, timeout=45); code = r.getcode()
    except HTTPError as e:
        code = e.code
    except Exception as e:
        code = "ERR:%s" % e
    print("  click HTTP %s" % code)
    return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", choices=["oracle", "python"], default="python")
    a = ap.parse_args()
    api = A.Api(transport="pc")
    gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
    print("=" * 62)
    print(" CORRECTED A/B -- arm=%s" % a.arm)
    print(" gps_adid=%s" % gps)
    print("=" * 62)
    t_click = fire_click(gps)
    maps, sec_install, ins = build_maps(api, gps, auid, t_click)
    print("  maps: %s" % ", ".join("%s(%d)" % (k, len(m)) for k, m in maps))

    if a.arm == "oracle":
        print("\nSTEP 2  signing on device (oracle)")
        auths = sign_on_device(maps, 3)
        if len(auths) < 3:
            print("  ORACLE FAILED: %d/3" % len(auths)); return 2
    else:
        print("\nSTEP 2  minting in python (aligned)")
        auths = mint_python(api, maps, sec_install)

    wait = (int(t_click) + int(CTIT)) - time.time()
    if wait > 0:
        print("\n  waiting %.0fs for CTIT..." % wait); time.sleep(wait)

    print("\nSTEP 3  sending install (session + sdk_click)")
    c, b = send_raw(api, "/session", maps[0][1], auths[0]); print("  /session   -> %s %s" % (c, b[:110]))
    c, b = send_raw(api, "/sdk_click", maps[1][1], auths[1]); print("  /sdk_click -> %s %s" % (c, b[:110]))

    print("\nSTEP 4  polling attribution")
    verdict = None
    for i in range(5):
        time.sleep(1 if i == 0 else 12)
        c, b = send_raw(api, "/attribution", maps[2][1], auths[2], method="GET")
        v = A.read_verdict(b)
        if v:
            verdict = v
            print("  poll %d %s token=%s eng=%s => %s" % (i + 1, c, v["token"], v["engagement_time"], v["verdict"]))
            if not v["organic"]:
                break
        else:
            print("  poll %d %s (no verdict) %s" % (i + 1, c, b[:110]))
    print("\n" + "=" * 62)
    print(" VERDICT: %s" % (verdict["verdict"] if verdict else "NO VERDICT"))
    print("=" * 62)
    with open(os.path.join(HERE, "oracle_ab2_%s.json" % a.arm), "w") as f:
        json.dump({"arm": a.arm, "gps_adid": gps, "verdict": verdict}, f, indent=1)
    print("saved oracle_ab2_%s.json" % a.arm)


if __name__ == "__main__":
    main()
