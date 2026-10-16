# -*- coding: utf-8 -*-
"""bubble_ah_variants.py -- offer 22353289 (campaign AH) click shapes.

The new offer maps to the SAME Adjust tracker 1t8ghv6f but a different
campaign:
    22352108 -> campaign GWM  adgroup {43407}   (booked nothing)
    22353289 -> campaign AH   adgroup 43407
So the join is the open question.  Four shapes, fresh idfa each:

  A  offer 22353289 verbatim      (gps_adid=<idfa>)
  B  offer 22353289 + idfa=       (both device params)
  C  user's direct link           (GWM, idfa only, NO click_id)
  D  direct AH link               (campaign AH + adgroup 43407, idfa, click_id)
"""
import json
import os
import re
import sys
import time
import uuid

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_bubble as B

OFFER_AH = ("http://click-adshustle.appanalytics.in/api/track/v1/click"
            "?aff_id=2&offer_id=22353289&sub1=2&sub2=vecwx2&sub3={gaid}")
DIRECT_USER = ("https://app.adjust.com/1t8ghv6f?campaign=GWM"
               "&adgroup=%7B43407%7D&cost_type=cpi&cost_amount=1"
               "&cost_currency=USD&idfa={idfa}")


def tracker_link(offer_tmpl, idfa):
    r = requests.get(offer_tmpl.replace("{gaid}", idfa),
                     headers={"User-Agent": B.BROWSER_UA},
                     allow_redirects=False, timeout=30)
    loc = r.headers.get("Location") or ""
    if "app.adjust.com" not in loc:
        raise RuntimeError("no Adjust link: %s" % loc[:120])
    return loc


def funnel(label, url_for):
    idfa = str(uuid.uuid4()).upper()
    T0 = int(time.time())
    B._IDFA, B._IDFV, B._DEDUPE = idfa, str(uuid.uuid4()).upper(), str(uuid.uuid4())
    B._STARTED, B._INSTALL = T0 - 1020, T0 - 29
    url = url_for(idfa)
    print("=" * 76)
    print("%s    idfa=%s" % (label, idfa))
    print("  click: %s" % url[:160])
    print("=" * 76, flush=True)

    st, hdrs, text = B._get(url)
    loc = hdrs.get("location") or ""
    print("  click HTTP %s  loc=%s" % (st, (loc[:90] or "(none)")))
    time.sleep(max(0, T0 + B.CIT - time.time()))

    sf = B.build_session_request(B.signing_second())
    ssec = B.signing_second()
    sf = B.build_session_request(ssec)
    sst, sbody = B._call("POST", "/session", sf, B._sign(sf, "session", ssec))
    try:
        p = json.loads(sbody)
        adid, ask_in = p.get("adid"), p.get("ask_in")
    except ValueError:
        adid, ask_in = None, None
    print("  session -> %s adid %s ask_in %s" % (sst, adid, ask_in), flush=True)
    init_by = "backend" if ask_in is not None else "sdk"

    tsec = B.signing_second()
    tf = B.build_tps_request(tsec)
    B._call("POST", "/third_party_sharing", tf, B._sign(tf, "third_party_sharing", tsec))

    csec = B.signing_second()
    cf = B.build_click_request(csec, None, T0)
    cst, _ = B._call("POST", "/sdk_click", cf, B._sign(cf, "click", csec))
    print("  sdk_click -> %s" % cst, flush=True)

    verdict = {}
    for i, pause in enumerate((2.8, 1.4, 20, 20, 20)):
        time.sleep(pause)
        asec = B.signing_second()
        af = B.build_attribution_request(asec, init_by)
        _s, abody = B._call("GET", "/attribution", af, B._sign(af, "attribution", asec))
        try:
            verdict = (json.loads(abody).get("attribution") or {})
        except ValueError:
            pass
        print("  poll %d -> %-12s / %-9s  campaign=%s adgroup=%s"
              % (i + 1, verdict.get("network"), verdict.get("tracker_token"),
                 verdict.get("campaign"), verdict.get("adgroup")), flush=True)
        if verdict.get("network") and verdict["network"] != "Organic":
            break
    print()
    return verdict


if __name__ == "__main__":
    res = {}
    res["A AH verbatim"] = funnel(
        "A  offer 22353289 verbatim (gps_adid)",
        lambda i: tracker_link(OFFER_AH, i))

    def b_with_idfa(i):
        return tracker_link(OFFER_AH, i) + "&idfa=" + i
    res["B AH + idfa"] = funnel("B  offer 22353289 + idfa=", b_with_idfa)

    res["C user direct"] = funnel(
        "C  user's direct link (GWM, no click_id)",
        lambda i: DIRECT_USER.replace("{idfa}", i))

    def d_direct_ah(i):
        return ("https://app.adjust.com/1t8ghv6f?campaign=AH&adgroup=43407"
                "&cost_type=cpi&cost_amount=1&cost_currency=USD"
                "&idfa=" + i + "&gps_adid=" + i
                + "&click_id=z" + uuid.uuid4().hex[:12])
    res["D direct AH"] = funnel(
        "D  direct AH link (idfa+gps_adid+click_id)", d_direct_ah)

    print("=" * 76)
    print("SUMMARY")
    for k, v in res.items():
        print("  %-16s %-12s / %-9s  %s / %s"
              % (k, v.get("network"), v.get("tracker_token"),
                 v.get("campaign"), v.get("adgroup")))
    paid = [k for k, v in res.items() if v.get("network") not in (None, "Organic")]
    print()
    print("BOOKED:", paid or "none")