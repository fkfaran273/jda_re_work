# -*- coding: utf-8 -*-
"""android_gaid_variants.py -- does the GAID FORMAT decide the join?

The click 302 points at market://details?id=com.bugbomb.dumptruckjam, so the
tracker/app pairing is right, yet the install stays Organic.  One untested
difference: we send a DASHED lowercase uuid as gps_adid.  Real Android
advertising IDs are 32 hex chars with NO dashes.  If Adjust normalises the
click side (strip dashes / case) but not the session side, the two never
compare equal and the join silently fails.

  G1  dashed lower   56ddbf71-e187-42fd-85df-9ef2f771a07a   (what we sent)
  G2  32-hex lower   56ddbf71e18742fd85df9ef2f771a07a
  G3  32-hex UPPER   56DDBF71E18742FD85DF9EF2F771A07A
"""
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_bubble_android as A


def funnel(label, gaid):
    auuid = str(uuid.uuid4())
    started = time.time()
    print("=" * 76)
    print("%s\ngaid=%s" % (label, gaid))
    print("=" * 76, flush=True)

    reftag, fired = A.open_direct_link(gaid)
    if not reftag:
        print("  no reftag -- abort")
        return {}
    print("  click reftag %s" % reftag[:110], flush=True)
    click_second = int(fired)
    time.sleep(max(0, click_second + 25 - time.time()))

    sec = A.signing_second()
    sf = A.build_session(gaid, auuid, sec, click_second)
    st, body = A.call("POST", "/session", sf, A.sign(sf, "session", sec))
    print("  session -> %s %s" % (st, body[:110]), flush=True)
    try:
        ask_in = json.loads(body).get("ask_in")
    except ValueError:
        ask_in = None

    csec = A.signing_second()
    cf = A.build_click(gaid, auuid, csec, reftag, click_second)
    cst, _ = A.call("POST", "/sdk_click", cf, A.sign(cf, "click", csec))
    print("  sdk_click -> %s" % cst, flush=True)

    verdict = {}
    for i in range(6):
        time.sleep(3.2 if i == 0 else (1.5 if i == 1 else 12))
        asec = A.signing_second()
        af = A.build_attr(gaid, auuid, asec)
        _s, b = A.call("GET", "/attribution", af, A.sign(af, "attribution", asec))
        try:
            p = json.loads(b)
        except ValueError:
            continue
        verdict = p.get("attribution") or {}
        print("  poll %d -> %-10s / %-9s  %s"
              % (i + 1, verdict.get("network"), verdict.get("tracker_token"),
                 verdict.get("tracker_name")), flush=True)
        if verdict.get("network") and verdict["network"] != "Organic":
            break
    print("  (%.0fs)" % (time.time() - started))
    print()
    return verdict


if __name__ == "__main__":
    u = str(uuid.uuid4())
    res = {}
    res["G1 dashed lower"] = funnel("G1  dashed lowercase uuid", u)
    res["G2 32-hex lower"] = funnel("G2  32-hex lowercase", u.replace("-", ""))
    res["G3 32-hex UPPER"] = funnel("G3  32-hex UPPERCASE",
                                    u.replace("-", "").upper())

    print("=" * 76)
    print("SUMMARY")
    for k, v in res.items():
        print("  %-18s %-10s / %-9s  %s"
              % (k, v.get("network"), v.get("tracker_token"),
                 v.get("tracker_name")))
    paid = [k for k, v in res.items() if v.get("network") not in (None, "Organic")]
    print()
    print("BOOKED:", paid or "none")