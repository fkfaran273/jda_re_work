"""Audit: run the SHIPPED runner's builders with the capture's inputs and
diff field sets + values vs the genuine requests."""
import json
import os
import re
import sys
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "..", "adj7"))
sys.path.insert(0, BASE)

from verify_from_scratch import CAPS, parse_request, request_fields

import run_install as R


def ts(v):
    if not v:
        return None
    m = re.match(r"(.*?)\.(\d+)Z([+-]\d{4})?$", v)
    if not m:
        return None
    d = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    tz = m.group(3) or "+0000"
    off = (1 if tz[0] == "+" else -1) * (int(tz[1:3]) * 3600
                                         + int(tz[3:5]) * 60)
    return calendar.timegm(d.timetuple()) - off


import calendar


def genuine(cap, sid):
    d = os.path.join(CAPS, cap, "raw")
    data = open(os.path.join(d, sid + "_c.txt"), "rb").read()
    meth, pth, hdrs, body = parse_request(data)
    return meth, pth, hdrs, request_fields(meth, pth, body)


def diff(name, gen, ours, time_keys):
    gk, ok_ = set(gen), set(ours)
    print("== %s" % name)
    if gk - ok_:
        print("   ONLY-IN-GENUINE : %s" % sorted(gk - ok_))
    if ok_ - gk:
        print("   ONLY-IN-RUNNER  : %s" % sorted(ok_ - gk))
    for k in sorted(gk & ok_):
        g, o = gen[k], ours[k]
        if k in time_keys and ts(g) and ts(o):
            delta = ts(o) - ts(g)
            if delta:
                print("   %-24s time-delta %+ds" % (k, delta))
            continue
        if g != o:
            print("   %-24s genuine=%r" % (k, g[:70]))
            print("   %-24s runner =%r" % ("", str(o)[:70]))
    print()


# ---- genuine inputs from payruki_again (Oct 7 device capture) ----
meth, pth, hdrs, gen_session = genuine("payruki_again", "32")
_, _, _, gen_click = genuine("payruki_again", "33")
_, _, _, gen_attr = genuine("payruki_again", "34")
_, _, _, gen_event = genuine("payruki_again", "36")

gaid = gen_session["gps_adid"]
auuid = gen_session["android_uuid"]

# the genuine time anchors
click_sec = ts(gen_click["click_time"])
sess_sec = ts(gen_session["created_at"])

# ---- reproduce the runner's outputs with the SAME inputs ----
R.ADJ_CLICK_SEC = click_sec
R.CIT = sess_sec - click_sec          # the genuine CTIT
R.FF_DELAY = None
r_session = R.build_session_request(gaid, auuid, sess_sec,
                                    click_sec=click_sec)
r_click = R.build_click_request(gaid, auuid, sess_sec + 1,
                                gen_click["referrer"],
                                click_sec=click_sec)
r_attr = R.build_attribution_request(gaid, auuid, sess_sec + 3)

TIME_KEYS = {"created_at", "sent_at", "installed_at", "updated_at",
             "click_time", "click_time_server", "install_begin_time",
             "install_begin_time_server"}

diff("SESSION (payruki_again sid32)", gen_session, r_session, TIME_KEYS)
diff("CLICK (payruki_again sid33)", gen_click, r_click, TIME_KEYS)
diff("ATTRIBUTION (payruki_again sid34)", gen_attr, r_attr, TIME_KEYS)

print("genuine event fields (runner has NO event step): %d fields" %
      len(gen_event))
print("  extra vs session: %s" % sorted(
    set(gen_event) - set(gen_session)))
print()
print("genuine attribution query order: %s" % list(gen_attr.keys()))
