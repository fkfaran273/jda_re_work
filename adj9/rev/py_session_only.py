# py_session_only.py - crafted /session ONLY (NO crafted /sdk_click), then the
# device oracle reads that crafted-created record.
#
# Why: every prior crafted run sent a crafted /sdk_click carrying the tracker's
# reftag as `referrer`. The app itself NEVER sends the tracker's reftag to
# /sdk_click - its referrer comes from Play and on this device is
# `utm_source=(not set)&utm_medium=(not set)` (farm_win: installReferrer).
# Sending the reftag there may create a conflicting click record that blocks the
# join. Omitting it isolates the session.
import datetime as dt
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
import farm_win as fw
from py_wire_test import wire, send, session_map

OUT = os.path.join(HERE, "py_session_only_result.json")
LOG = {}


def log(k, v):
    LOG[k] = v
    print("[%s] %s" % (k, v), flush=True)


def iso(ts, ms=0):
    d = (dt.datetime.fromtimestamp(ts, dt.timezone.utc)
         + dt.timedelta(hours=5, minutes=30))
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def main():
    marker = "cline_sess_h"
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    log("identity", "gps=%s marker=%s" % (gps, marker))

    got = fw.set_gaid(gps)
    log("gaid", "readback %s %s" % (got, "OK" if got == gps else "MISMATCH"))
    if got != gps:
        raise SystemExit("GAID readback mismatch")

    t_click = time.time()
    try:
        code, ref, hops, url = fw.fire_click(gps, marker, None)
        log("click", "http=%s at %s reftag=%s"
            % (code, iso(t_click, 0), (ref or "")[:44]))
    except Exception as e:
        log("click", "FAILED %s: %s" % (type(e).__name__, str(e)[:110]))
        ref = None

    wait = 10
    print("[gap] %ds for a positive CTIT" % wait, flush=True)
    time.sleep(wait)
    t_install = time.time()
    second = int(t_install)

    val = session_map()
    val.update({
        "gps_adid": gps, "android_uuid": auid,
        "created_at": iso(t_install, 100), "sent_at": iso(t_install, 130),
        "installed_at": iso(t_install, 0), "updated_at": iso(t_install, 0),
        "session_count": "1", "activity_kind": "session",
        "gps_adid_attempt": "1", "gps_adid_src": "service",
        "tracking_enabled": "1",
    })
    st, blob, _, unp = F.make_signature_law(val, "session", second=second)
    log("session", "%s #10=%dB  CTIT=+%.1fs"
        % (st, unp, t_install - t_click))
    c, b = send("POST", "/session", wire(val), blob)
    log("session/send", "%s %s" % (c, b[:220]))
    log("sdk_click", "SKIPPED by design (the app never sends the tracker's reftag)")

    for attempt in range(2):
        time.sleep(10 if attempt == 0 else 20)
        av = dict(val)
        av.update({"activity_kind": "attribution", "initiated_by": "backend"})
        for k in ("session_count", "installed_at", "updated_at", "hardware_name",
                  "os_build", "initiating_package_name",
                  "store_name_from_system"):
            av.pop(k, None)
        try:
            st3, blob3, _, n3 = F.make_signature_law(av, "attribution",
                                                     second=int(time.time()))
            c3, b3 = send("GET", "/attribution", wire(av), blob3)
            log("attribution/%d" % attempt, "%s %s" % (c3, b3[:200]))
        except Exception as e:
            log("attribution/%d" % attempt,
                "%s: %s" % (type(e).__name__, str(e)[:110]))

    LOG.update({"gps": gps, "marker": marker, "installed_iso": val["installed_at"]})
    json.dump(LOG, open(OUT, "w"), indent=1)
    print("\nsaved %s" % OUT, flush=True)
    print("NOW: python py_verdict.py %s %s" % (gps, marker), flush=True)


if __name__ == "__main__":
    main()