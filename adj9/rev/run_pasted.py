"""run_pasted.py — winner-shape replay with pasted inputs (no link click).

Paste below and Run (no CLI args needed):
  GPS         clicked gps adid ("" = fresh random install id)
  DEVICE_JSON device-data JSON (raw or file path; "" = moto g42 winner shape)
  REFERRER    install referrer string ("" = winner "(not set)" shape)
  CLICK_ISO   click_time, exact string (default: M4 2026-09-14T17:48:35.000Z+0530)
  BEGIN_ISO   install_begin_time ("" = click + 30 s)
  INSTALLED_ISO installed_at ("" = click + 273 s, M4-like CTIT)

Flow: session -> sdk_click (pasted referrer + click times, -2 s server
skews) -> attribution x2 (ask_in -> backend else sdk). All adj9-signed.
M4 wire shape: 43-param session (no install_version), 47-param click,
22-param attribution (initiated_by first, NO push_token), NO sdk_info,
language tr, no mcc/mnc.
"""
import datetime
import json
import os
import secrets
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as F
from run_funnel import dev_from_json, ua_from_json

# ================= PASTE HERE =================
GPS = ""
DEVICE_JSON = """"""
REFERRER = ""
CLICK_ISO = "2026-09-14T17:48:35.000Z+0530"
BEGIN_ISO = ""
INSTALLED_ISO = ""
# ==============================================


def parse_iso(s):
    s = s.strip().replace("Z", "")
    for f in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
              "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            d = datetime.datetime.strptime(s, f)
            if d.tzinfo is None:
                d = d.replace(tzinfo=datetime.timezone.utc)
            return int(d.timestamp()), d
        except Exception:
            pass
    raise ValueError("bad ISO: %r" % s)


def main():
    gps = GPS or str(uuid.uuid4())
    print("install gps:", gps, "(pasted)" if GPS else "(fresh)",
          flush=True)
    devsrc = (DEVICE_JSON or "").strip()
    if devsrc.startswith("{"):
        devj = json.loads(devsrc)
        F.DEV, F.UA = dev_from_json(devj), ua_from_json(devj)
    elif devsrc:
        devj = json.load(open(devsrc))
        F.DEV, F.UA = dev_from_json(devj), ua_from_json(devj)
    else:
        F.DEV, F.UA = dict(F.MOTO), F.MOTO_UA
    F.OFF_MINUTES, F.OFF_LABEL = 120, "+0200"
    F.ADD_IDFA = False  # winner shape: no click_id/idfa (mirror-faithful)
    os.environ["HTTP_PROXY"] = "http://127.0.0.1:8888"
    os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8888"
    F.USE_PROXY = True
    print("proxy ON via Fiddler (same as run_funnel)", flush=True)
    auid = str(uuid.uuid4())
    print("auid", auid, flush=True)

    # Winner wire bytes are double-encoded (%2520): the Play Referrer API
    # returns the string already containing %20, form-encoding turns %->%25.
    # Real spaces would wire as + instead -> different string post-decode
    # AND different HMAC (referrer is HMAC-covered on click calls).
    ref = REFERRER or "utm_source=(not%20set)&utm_medium=(not%20set)"
    print("REFERRER:", ref, flush=True)
    t_track, _dt = parse_iso(CLICK_ISO)
    _off = _dt.utcoffset()
    if _off is not None:
        F.OFF_MINUTES = int(_off.total_seconds() // 60)
        _s = F.OFF_MINUTES
        F.OFF_LABEL = "%s%02d%02d" % ("+" if _s >= 0 else "-",
                                      abs(_s) // 60, abs(_s) % 60)
        print("tz from click:", F.OFF_LABEL, flush=True)
    if BEGIN_ISO:
        t_begin, _ = parse_iso(BEGIN_ISO)
    else:
        t_begin = t_track + 30
    if INSTALLED_ISO:
        _ie, _idt = parse_iso(INSTALLED_ISO)
        _ims = _idt.microsecond // 1000
        ins = F.fmt(_ie, _ims)  # normalized to 29 chars, same instant+tz
    else:
        ins = F.fmt(t_track + 273, 431)  # M4-like CTIT, profile tz
    print("click", t_track, "begin", t_begin, "installed", ins.decode(),
          flush=True)

    print("STEP 1/3 session...", flush=True)
    s2, r2 = F.api_session(gps, auid, ins)
    print("SESSION:", s2, r2[:200], flush=True)
    time.sleep(3)

    print("STEP 2/3 sdk_click...", flush=True)
    s1, r1 = F.api_sdk_click(gps, auid, ref, t_track, t_begin, ins)
    print("CLICK:", s1, r1[:200], flush=True)
    time.sleep(3)

    print("STEP 3/3 attribution x2...", flush=True)
    ptoken = ("e" + secrets.token_urlsafe(24) + ":APA91b"
              + secrets.token_urlsafe(96))
    try:
        _ask = json.loads(r2).get("ask_in", 0) or 0
    except Exception:
        _ask = 0
    try:
        _ask = max(_ask, json.loads(r1).get("ask_in", 0) or 0)
    except Exception:
        pass
    _ib = "backend" if _ask else "sdk"
    if _ask:
        _wait = min(_ask / 1000.0, 180.0)
        print("ask_in=%dms -> %s, wait %.0fs" % (_ask, _ib, _wait),
              flush=True)
        time.sleep(_wait)
    else:
        print("no ask_in -> sdk", flush=True)
    s3, r3 = F.api_attribution(gps, auid, ptoken, _ib)
    print("ATTR:", s3, r3[:600], flush=True)
    time.sleep(10)
    s3, r3 = F.api_attribution(gps, auid, ptoken, _ib)
    print("ATTR:", s3, r3[:2000], flush=True)
    try:
        a = json.loads(r3)["attribution"]
        net = "%s/%s" % (a.get("tracker_token"), a.get("network"))
    except Exception:
        net = "?"
    print("VERDICT:", net, flush=True)
    json.dump({"gps": gps, "auid": auid, "referrer": ref,
               "click_iso": CLICK_ISO, "installed": ins.decode(),
               "session": [s2, r2[:300]], "click": [s1, r1[:300]],
               "attr": [s3, r3[:2000]], "verdict": net},
              open(os.path.join(HERE, "run_pasted_result.json"), "w"),
              indent=1)


if __name__ == "__main__":
    main()
