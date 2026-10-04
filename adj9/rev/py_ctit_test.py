# py_ctit_test.py - crafted chain with a REALISTIC positive CTIT.
#
# Defect found by comparing timestamps with the winning run:
#   farm_win winner : click 20:49:53 -> installed_at 20:50:01   CTIT = +8 s
#   our crafted    : click at  ~T    -> installed_at = T-2       CTIT = NEGATIVE
# i.e. every crafted install we ever sent told the server it was installed
# BEFORE the click that is supposed to have caused it. A click->install join
# cannot be made from a negative CTIT.
#
# This run: fire the click, WAIT ~10 s, then send the crafted /session with
# installed_at = now (after the click), and the crafted /sdk_click with
# click_time = (click moment) and install_begin_time = +8 s.
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
from py_wire_test import wire, send, session_map, click_map

OUT = os.path.join(HERE, "py_ctit_result.json")
LOG = {}


def log(k, v):
    LOG[k] = v
    print("[%s] %s" % (k, v), flush=True)


def iso(ts, ms=0):
    d = (dt.datetime.fromtimestamp(ts, dt.timezone.utc)
         + dt.timedelta(hours=5, minutes=30))
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def main():
    marker = "cline_ctit_g"
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
            % (code, iso(t_click, 100), (ref or "")[:44]))
    except Exception as e:
        ref = None
        log("click", "FAILED %s: %s" % (type(e).__name__, str(e)[:110]))

    # ---- the fix: WAIT so the install strictly follows the click ------------
    wait = 10
    print("[gap] waiting %ds so installed_at > click_time (positive CTIT)" % wait,
          flush=True)
    time.sleep(wait)

    t_install = time.time()
    second = int(t_install)
    val = session_map()
    val.update({
        "gps_adid": gps, "android_uuid": auid,
        "created_at": iso(t_install, 100),
        "sent_at": iso(t_install, 130),
        "installed_at": iso(t_install, 0),          # AFTER the click
        "updated_at": iso(t_install, 0),
        "session_count": "1", "activity_kind": "session",
        "gps_adid_attempt": "1", "gps_adid_src": "service",
        "tracking_enabled": "1",
    })
    log("timing", "click=%s  installed_at=%s  CTIT=+%.1fs"
        % (iso(t_click, 100), val["installed_at"], t_install - t_click))
    st, blob, _, unp = F.make_signature_law(val, "session", second=second)
    c, b = send("POST", "/session", wire(val), blob)
    log("session/send", "%s %s" % (c, b[:200]))

    cm = click_map()
    if cm and ref:
        cm.update({
            "gps_adid": gps, "android_uuid": auid,
            "created_at": iso(t_install, 100), "sent_at": iso(t_install, 130),
            "installed_at": iso(t_install, 0), "updated_at": iso(t_install, 0),
            "session_count": "1", "activity_kind": "click",
            "gps_adid_attempt": "1", "gps_adid_src": "service",
            "tracking_enabled": "1", "google_play_instant": "0",
            "referrer": ref, "referrer_api": "google",
            "source": "install_referrer", "session_length": "0",
            "subsession_count": "1", "time_spent": "0",
            "click_time": iso(t_click, 0),
            "click_time_server": iso(t_click - 2, 0),
            "install_begin_time": iso(t_install - 1, 200),
            "install_begin_time_server": iso(t_install - 1, 200),
        })
        try:
            st2, blob2, _, n2 = F.make_signature_law(cm, "click", second=second)
            c2, b2 = send("POST", "/sdk_click", wire(cm), blob2)
            log("sdk_click/send", "%s %s" % (c2, b2[:200]))
        except Exception as e:
            log("sdk_click/send", "%s: %s" % (type(e).__name__, str(e)[:130]))

    for attempt in range(3):
        time.sleep(10 if attempt == 0 else 25)
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

    LOG.update({"gps": gps, "marker": marker, "click_iso": iso(t_click, 100),
                "installed_iso": val["installed_at"]})
    json.dump(LOG, open(OUT, "w"), indent=1)
    print("\nsaved %s" % OUT, flush=True)
    print("NOW: python py_verdict.py %s %s" % (gps, marker), flush=True)


if __name__ == "__main__":
    main()