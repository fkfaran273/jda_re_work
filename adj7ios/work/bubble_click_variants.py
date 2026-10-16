# -*- coding: utf-8 -*-
"""bubble_click_variants.py -- which click shape makes BubbleBus join?

The adshustle tracker only ever emits gps_adid=<sub3>.  On iOS the device
match is idfa=, so I add it -- but the trimmed both-param link still came
back Organic.  Test the plausible shapes end-to-end, fresh idfa each:

  A  tracker verbatim      (gps_adid=<idfa> only, full cost/callback params)
  B  trimmed both          (idfa + gps_adid, minimal)          [already Organic]
  C  tracker link + idfa   (full param set, idfa appended)
  D  idfa only             (gps_adid removed)

A booking shows up as a non-Organic network on the first poll.
"""
import json
import os
import sys
import time
import urllib.parse
import uuid

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_bubble as B

TRACKER = ("http://click-adshustle.appanalytics.in/api/track/v1/click"
           "?aff_id=2&offer_id=22352108&sub1=2&sub2=vecwx2&sub3={gaid}")


def tracker_adjust_link(idfa):
    """Fire the tracker with sub3=idfa, return its Adjust Location verbatim."""
    r = requests.get(TRACKER.replace("{gaid}", idfa),
                     headers={"User-Agent": B.BROWSER_UA},
                     allow_redirects=False, timeout=30)
    loc = r.headers.get("Location") or ""
    if "app.adjust.com" not in loc:
        raise RuntimeError("tracker gave no Adjust link: %s" % loc[:120])
    return loc


def funnel(label, url_for):
    idfa = str(uuid.uuid4()).upper()
    T0 = int(time.time())
    B._IDFA, B._IDFV, B._DEDUPE = idfa, str(uuid.uuid4()).upper(), str(uuid.uuid4())
    B._STARTED, B._INSTALL = T0 - 1020, T0 - 29
    url = url_for(idfa)
    print("=" * 74)
    print("%s   idfa=%s" % (label, idfa))
    print("  click: %s" % url[:150])
    print("=" * 74, flush=True)

    # fire the click ourselves so we can inspect the answer
    st, hdrs, text = B._get(url)
    print("  click HTTP %s" % st)
    loc = hdrs.get("location") or ""
    print("  click Location: %s" % (loc[:140] if loc else "(none)"))
    print("  click echoes click_id: %s" % ("click_id=" in (loc or text)))

    time.sleep(max(0, T0 + B.CIT - time.time()))

    def auth(f, kind, sec):
        return B._sign(f, kind, sec)

    sec = B.signing_second()
    sst, sbody = B._call("POST", "/session", B.build_session_request(sec),
                         auth(B.build_session_request(sec), "session", sec))
    try:
        p = json.loads(sbody)
        adid, ask_in = p.get("adid"), p.get("ask_in")
    except ValueError:
        adid, ask_in = None, None
    print("  session -> %s adid %s ask_in %s" % (sst, adid, ask_in))
    init_by = "backend" if ask_in is not None else "sdk"

    tsec = B.signing_second()
    B._call("POST", "/third_party_sharing", B.build_tps_request(tsec),
            auth(B.build_tps_request(tsec), "third_party_sharing", tsec))

    csec = B.signing_second()
    cst, _ = B._call("POST", "/sdk_click",
                     B.build_click_request(csec, None, T0),
                     auth(B.build_click_request(csec, None, T0), "click", csec))
    print("  sdk_click -> %s" % cst)

    verdict = {}
    for i, pause in enumerate((2.8, 1.4, 20, 20)):
        time.sleep(pause)
        asec = B.signing_second()
        af = B.build_attribution_request(asec, init_by)
        _s, abody = B._call("GET", "/attribution", af, auth(af, "attribution", asec))
        try:
            verdict = (json.loads(abody).get("attribution") or {})
        except ValueError:
            pass
        print("  poll %d -> %-12s / %-9s" % (i + 1, verdict.get("network"),
                                             verdict.get("tracker_token")),
              flush=True)
        if verdict.get("network") and verdict["network"] != "Organic":
            break
    print()
    return verdict


if __name__ == "__main__":
    results = {}

    # A: the tracker's own link, verbatim (gps_adid only)
    results["A tracker verbatim"] = funnel(
        "A  tracker verbatim (gps_adid only)",
        lambda idfa: tracker_adjust_link(idfa))

    # C: tracker link + idfa appended (full param set)
    def with_idfa(idfa):
        loc = tracker_adjust_link(idfa)
        sep = "&" if "?" in loc else "?"
        return loc + sep + "idfa=" + idfa
    results["C tracker + idfa"] = funnel("C  tracker link + idfa=", with_idfa)

    # D: idfa only, gps_adid stripped
    def idfa_only(idfa):
        loc = tracker_adjust_link(idfa)
        loc = loc.replace("gps_adid=" + idfa, "gps_adid=")
        return loc
    results["D idfa only"] = funnel("D  idfa only (gps_adid emptied)",
                                   idfa_only)

    print("=" * 74)
    print("SUMMARY")
    for k, v in results.items():
        print("  %-22s %-12s / %s" % (k, v.get("network"),
                                      v.get("tracker_token")))
    paid = [k for k, v in results.items()
            if v.get("network") not in (None, "Organic")]
    print()
    print("BOOKED variants:", paid or "none")