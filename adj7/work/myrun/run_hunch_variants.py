"""Variant screen: which click-URL param binds the click to our gaid.

Links (user's exact base + device-id slot), one fresh gaid + full install each:
  sub3= / adid= / gaid= / idfa= / gps_adid=
Records verdict per variant to variants_result.json.
"""
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_hunch as H

BASE = ("https://app.adjust.com/1yzhva5b?campaign=SOHYPE_ADH"
        "&adgroup={affiliate_id}&creative=[app_name}")
VARIANTS = ["sub3", "adid", "gaid", "idfa", "gps_adid"]

results = []


def fire_click(url, tag):
    clog = open(os.path.join(HERE, "click_chain_hunch_var.log"), "a")
    clog.write("=== %s variant=%s url=%s\n"
               % (__import__("datetime").datetime.now().isoformat(), tag, url))
    try:
        st, hd, _ = H._click_get(url)
        loc = hd.get("Location") or hd.get("location") or ""
        clog.write(" -> %s loc=%s\n" % (st, loc[:280]))
        ref = H._reftag_in(loc)
        if ref:
            clog.write(" ref=%s\n" % ref)
            return ref
        if loc.startswith("http"):
            st2, hd2, _ = H._click_get(loc)
            loc2 = hd2.get("Location") or hd2.get("location") or ""
            clog.write(" hop2 -> %s loc=%s\n" % (st2, loc2[:280]))
            ref = H._reftag_in(loc2)
            if ref:
                clog.write(" ref=%s\n" % ref)
                return ref
        return None
    finally:
        clog.close()


def one_run(variant):
    gaid = str(uuid.uuid4())
    android_uuid = str(uuid.uuid4())
    url = "%s&%s=%s" % (BASE, variant, gaid)
    print("### variant=%s gaid=%s" % (variant, gaid), flush=True)
    print("click: %s" % url, flush=True)
    t0 = time.time()
    ref = fire_click(url, variant)
    if not ref:
        print("no reftag -- variant failed", flush=True)
        return {"variant": variant, "gaid": gaid, "error": "no-reftag"}
    print("reftag %s" % ref, flush=True)
    click_second = int(time.time()) - 1
    wait = click_second + H.SESSION_AT - time.time()
    if wait > 0:
        time.sleep(wait)
    sec = H.signing_second()
    sf = H.build_session(gaid, android_uuid, sec, click_second)
    st, b = H.call("POST", "/session", sf, H.sign(sf, "session", sec))
    adid = json.loads(b).get("adid", "")
    print("session %s adid=%s" % (st, adid), flush=True)
    time.sleep(0.3)
    sec2 = H.signing_second()
    cf = H.build_click(gaid, android_uuid, sec2, ref, click_second)
    st2, _b2 = H.call("POST", "/sdk_click", cf, H.sign(cf, "click", sec2))
    print("sdk_click %s" % st2, flush=True)
    verdict = {}
    for i in range(4):
        time.sleep(3.2 if i == 0 else 2.0)
        sec3 = H.signing_second()
        af = H.build_attr(gaid, android_uuid, sec3)
        _s, b3 = H.call("GET", "/attribution", af,
                        H.sign(af, "attribution", sec3))
        p3 = json.loads(b3)
        verdict = p3.get("attribution") or {}
        print("poll %d -> %s / %s ask_in=%s [t=+%.0fs]"
              % (i + 1, verdict.get("network"), verdict.get("tracker_token"),
                 p3.get("ask_in"), time.time() - t0), flush=True)
        if verdict.get("network") and verdict["network"] != "Organic":
            break
    rec = {"variant": variant, "gaid": gaid, "reftag": ref, "adid": adid,
           "network": verdict.get("network"),
           "tracker": verdict.get("tracker_token"),
           "engagement": verdict.get("engagement_time"),
           "ask_in_last": None, "secs": round(time.time() - t0)}
    results.append(rec)
    open(os.path.join(HERE, "variants_result.json"), "w").write(
        json.dumps(results, indent=1))
    return rec


for v in VARIANTS:
    try:
        r = one_run(v)
        print("RESULT %s -> %s / %s / %s" % (r["variant"], r.get("network"),
                                            r.get("tracker"), r.get("engagement")),
              flush=True)
        if r.get("network") not in (None, "Organic"):
            print("*** NON-ORGANIC on %s -- stopping screen ***" % v, flush=True)
            break
    except Exception as e:
        print("variant %s ERROR %r" % (v, e), flush=True)
        results.append({"variant": v, "error": repr(e)})
print("SCREEN DONE", flush=True)
