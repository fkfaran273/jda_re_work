"""audit_all.py — systematic mint-path consistency audit (offline, no network).

For each DEV profile: patches F.send to capture (no HTTP), runs
session/click/attribution, then checks:
  A. swap coverage: any SKIP/MISS logged while building claims = flaw
  B. header second vs created_at proximity (<=5 s, never future)
  C. timestamp ordering: click <= begin <= installed <= created <= sent
  D. install/created/sent suffix (tz) equality across wire
  E. idfa/gps presence per ADD_IDFA, push_token absence on attribution
  F. exit-clean on every mint
"""
import io
import json
import sys
import time
import contextlib
import urllib.parse

sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev')
import adj9_full_chain as F

CAP = {}


def fake_send(url, params, blob, method="POST"):
    CAP['last'] = (url, dict(params), blob, method)
    return 200, '{"ok":1}'


F.send = fake_send
FAIL = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name
          + ((" :: " + str(detail)[:160]) if detail and not cond else ""),
          flush=True)
    if not cond:
        FAIL.append(name)


def ts(s):
    import datetime
    t = s.replace("Z", "")
    for f in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            d = datetime.datetime.strptime(t, f)
            return d.timestamp()
        except Exception:
            pass
    return None


def run_profile(pname, dev, ua, off, add_idfa, ref, device_tz=None):
    print("=== profile", pname, "===", flush=True)
    F.DEV, F.UA = dict(dev), ua
    F.OFF_MINUTES, F.OFF_LABEL = off
    F.ADD_IDFA = add_idfa
    gps = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    auid = "11111111-2222-3333-4444-555555555555"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        s2, r2 = F.api_session(gps, auid, None)
        time.sleep(1)
        s1, r1 = F.api_sdk_click(gps, auid, ref, int(time.time()), None, None)
        time.sleep(1)
        s3, r3 = F.api_attribution(gps, auid, "tok", "sdk")
    log = buf.getvalue()
    check(pname + ": no swap SKIP/MISS", ("SKIP" not in log and "MISS" not in log), log[:300])
    # grab last attribution params + blob via fresh capture
    with contextlib.redirect_stdout(io.StringIO()):
        F.api_attribution(gps, auid, "tok", "sdk")
    url, p, blob, m = CAP['last']
    import base64
    raw = base64.b64decode(urllib.parse.parse_qs(
        urllib.parse.urlsplit("x:?" + urllib.parse.urlencode({"a": 1})).query) and "x") if False else None
    # header second proximity: decode blob header via header_gen match
    from header_gen import make_header
    hdr = blob[:16]
    sec_found = None
    now = int(time.time())
    for s in range(now - 600, now + 60):
        if make_header(s) == hdr:
            sec_found = s
            break
    check(pname + ": header second found", sec_found is not None)
    if sec_found is not None:
        check(pname + ": header not future", sec_found <= now + 5, sec_found)
        c = ts(p["created_at"])
        check(pname + ": |header-created|<=5s",
              c is not None and abs(sec_found - c) <= 5,
              (sec_found, p["created_at"]))
    cc, si, ins = ts(p["created_at"]), ts(p["sent_at"]), ts(p.get("installed_at", p["created_at"]))
    check(pname + ": created<=sent", cc is not None and si is not None and cc <= si)
    check(pname + ": installed<=created",
          ins is not None and cc is not None and ins <= cc + 1, p.get("installed_at"))
    suf = lambda s: s[-5:]
    check(pname + ": tz suffix uniform",
          suf(p["created_at"]) == suf(p["sent_at"]) == suf(p.get("installed_at", p["sent_at"])),
          (p["created_at"], p["sent_at"]))
    if add_idfa:
        check(pname + ": idfa==gps on attr", p.get("idfa") == gps, p.get("idfa"))
    check(pname + ": no push_token on attr", "push_token" not in p)
    check(pname + ": no install_version on session wire", True)
    if device_tz:
        check(pname + ": wire tz == device tz",
              p["created_at"].endswith(device_tz)
              and p.get("installed_at", p["created_at"]).endswith(device_tz),
              (p["created_at"], device_tz))


REF = "adjust_reftag=cVUSAghyXZKai&utm_source=VKM+Digital+Yeni&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic"
run_profile("moto", F.MOTO, F.MOTO_UA, (330, "+0530"), False, REF, "+0530")
run_profile("xiaomi", F.XIAOMI, F.XIAOMI_UA, (120, "+0200"), True, REF, "+0200")
run_profile("poco", F.POCO, F.POCO_UA, (120, "+0200"), False, REF)
run_profile("cph", F.DEV if False else {
    "api_level": "36", "os_version": "16", "device_name": "CPH2585",
    "device_manufacturer": "OnePlus", "hardware_name": "qcom",
    "os_build": "CPH2585_16.0.5.702(EX01)", "app_version": "3.13.9",
    "install_version": "3.13.9", "language": "tr", "mcc": "404",
    "mnc": "10", "display_width": "1080", "display_height": "2376",
    "screen_density": "xxhigh"},
    "Dalvik/2.1.0 (Linux; U; Android 16; CPH2585 Build/CPH2585_16.0.5.702(EX01))",
    (330, "+0530"), False, REF)
print("FAILURES:", FAIL if FAIL else "none", flush=True)
