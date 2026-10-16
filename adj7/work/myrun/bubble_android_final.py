# -*- coding: utf-8 -*-
"""bubble_android_final.py -- clean Android attempts on tracker 1t8ghv6f.

What we learned so far:
  * the tracker really is BubbleBus (302 -> market://details?id=com.bugbomb...)
  * the click is accepted and returns a reftag (adjust_reftag + utm_campaign)
  * sessions are device-unique (3 distinct adids) when gps_adid is a 32-hex
    GAID; the earlier 400s were the ~20 min per-adid session throttle
  * every install still reads Organic

Two clean attempts, patient polling:
  A1  32-hex UPPER gaid, no dedupe token
  A2  32-hex UPPER gaid + primary_dedupe_token (what a real SDK sends)
"""
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_bubble_android as A


def funnel(label, with_dedupe):
    gaid = uuid.uuid4().hex.upper()
    auuid = str(uuid.uuid4())
    print("=" * 76)
    print("%s\ngaid=%s" % (label, gaid))
    print("=" * 76, flush=True)

    reftag, fired = A.open_direct_link(gaid)
    if not reftag:
        print("  no reftag")
        return {}
    print("  click ok: %s" % reftag[:110], flush=True)
    click_second = int(fired)
    time.sleep(max(0, click_second + 25 - time.time()))

    sec = A.signing_second()
    sf = A.build_session(gaid, auuid, sec, click_second)
    if with_dedupe:
        sf["primary_dedupe_token"] = str(uuid.uuid4())
    st, body = A.call("POST", "/session", sf, A.sign(sf, "session", sec))
    print("  session -> %s %s" % (st, body[:120]), flush=True)
    try:
        ask_in = json.loads(body).get("ask_in")
    except ValueError:
        ask_in = None

    csec = A.signing_second()
    cf = A.build_click(gaid, auuid, csec, reftag, click_second)
    if with_dedupe:
        cf["primary_dedupe_token"] = sf["primary_dedupe_token"]
    cst, cbody = A.call("POST", "/sdk_click", cf, A.sign(cf, "click", csec))
    print("  sdk_click -> %s %s" % (cst, cbody[:100]), flush=True)

    verdict = {}
    for i in range(8):
        time.sleep(3.2 if i == 0 else (1.5 if i == 1 else 12))
        asec = A.signing_second()
        af = A.build_attr(gaid, auuid, asec)
        if with_dedupe:
            af["primary_dedupe_token"] = sf["primary_dedupe_token"]
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
    print()
    return verdict


if __name__ == "__main__":
    res = {}
    res["A1 no dedupe"] = funnel("A1  32-hex UPPER gaid, no dedupe token", False)
    time.sleep(5)
    res["A2 + dedupe"] = funnel("A2  32-hex UPPER gaid + dedupe token", True)

    print("=" * 76)
    print("SUMMARY")
    for k, v in res.items():
        print("  %-14s %-10s / %-9s  %s"
              % (k, v.get("network"), v.get("tracker_token"),
                 v.get("tracker_name")))
    paid = [k for k, v in res.items() if v.get("network") not in (None, "Organic")]
    print()
    print("BOOKED:", paid or "none")