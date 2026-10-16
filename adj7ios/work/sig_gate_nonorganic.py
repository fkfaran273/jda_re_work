# -*- coding: utf-8 -*-
"""sig_gate_nonorganic.py -- does a NON-ORGANIC attribution need a valid
signature?

Three full funnels, identical in every way EXCEPT the Authorization on the
session/sdk_click/attribution calls:
    valid   -> our real adj7-iOS mint
    broken  -> same shape, one body byte flipped
    none    -> all-zero blob
Each gets a FRESH idfa and a FRESH click on the booking link, so the join
has every chance to book.  If the verdict is paid in all three legs, the
non-organic response is not signature-gated.
"""
import json
import os
import re
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_berain as B

ZERO_AUTH = ('Signature signature="' + '00' * 304 +
             '",adj_signing_id="1300000",algorithm="adj7",headers_id="8",'
             'native_version="3.62.0"')


def flip(auth):
    m = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
    b = m.group(1)
    i = 60
    return auth.replace(b, b[:i] + ('0' if b[i] != '0' else '1') + b[i + 1:])


def funnel(mode):
    idfa = str(uuid.uuid4()).upper()
    T0 = int(time.time())
    B._IDFA = idfa
    B._IDFV = str(uuid.uuid4()).upper()
    B._DEDUPE = str(uuid.uuid4())
    B._STARTED, B._INSTALL = T0 - 1020, T0 - 29
    print("=== %s  idfa=%s" % (mode, idfa[:8]), flush=True)

    # 1. click (the booking link, real navigation)
    click_second = T0
    B.open_click_link(idfa)
    print("    click done", flush=True)
    time.sleep(max(0, click_second + B.CIT - time.time()))

    def auth_for(fields, kind):
        a = B._sign(fields, kind, B.signing_second())
        if mode == "broken":
            a = flip(a)
        elif mode == "none":
            a = ZERO_AUTH
        return a

    # 2. session
    sf = B.build_session_request(B.signing_second())
    st, body = B._call("POST", "/session", sf, auth_for(sf, "session"))
    print("    session -> %s %s" % (st, body[:110]), flush=True)
    try:
        adid = json.loads(body).get("adid")
        ask_in = json.loads(body).get("ask_in")
    except ValueError:
        adid, ask_in = None, None
    init_by = "backend" if ask_in is not None else "sdk"

    # 3. tps
    tf = B.build_tps_request(B.signing_second())
    B._call("POST", "/third_party_sharing", tf,
            auth_for(tf, "third_party_sharing"))

    # 4. sdk_click
    cf = B.build_click_request(B.signing_second(), None, click_second)
    B._call("POST", "/sdk_click", cf, auth_for(cf, "click"))

    # 5. attribution (double-ask + a short ladder)
    verdict = {}
    for i, pause in enumerate((2.8, 1.4, 20, 20)):
        time.sleep(pause)
        af = B.build_attribution_request(B.signing_second(), init_by)
        _st, body = B._call("GET", "/attribution", af,
                            auth_for(af, "attribution"))
        try:
            payload = json.loads(body)
        except ValueError:
            payload = {}
        verdict = payload.get("attribution") or {}
        print("    poll %d -> %s / %s"
              % (i + 1, verdict.get("network"),
                 verdict.get("tracker_token")), flush=True)
        if verdict.get("network") and verdict["network"] != "Organic":
            break
    return verdict


out = {}
for mode in ("valid", "broken", "none"):
    out[mode] = funnel(mode)
    time.sleep(2)
print()
print("=== VERDICTS")
for mode in ("valid", "broken", "none"):
    v = out[mode]
    print("  %-7s %-12s / %-9s  engagement=%s"
          % (mode, v.get("network"), v.get("tracker_token"),
             v.get("engagement_time")))
paid = {m: (out[m].get("network") not in (None, "Organic"))
        for m in ("valid", "broken", "none")}
print()
print("paid per leg:", paid)
if all(paid.values()):
    print(">>> NON-ORGANIC IS NOT SIGNATURE-GATED (all three booked)")
elif paid["valid"] and not paid["broken"] and not paid["none"]:
    print(">>> SIGNATURE-GATED: only the valid mint booked")
else:
    print(">>> mixed -- inspect the legs above")
