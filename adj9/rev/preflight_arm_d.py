"""preflight_arm_d.py — OFFLINE dry run of arm_d's exact param path.

Stubs only the slow Unicorn mint and the network send; every other line is the
real builder code, so the claim strings are what a live run would produce.
No click is fired and no GAID is generated or spent.
"""
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mint_pipeline as M
import run_funnel as RF
import adj9_full_chain as FC

CFG = json.load(open(os.path.join(HERE, "pixel7_click.json")))
DEV_JSON = CFG["DEV_JSON"]
GPS = CFG["GPS"]
REFERRER = CFG["REFERRER"]

FC.DEV = RF.dev_from_json(DEV_JSON)
FC.UA = RF.ua_from_json(DEV_JSON)
FC.OFF_MINUTES, FC.OFF_LABEL = CFG["OFF_MINUTES"], CFG["OFF_LABEL"]
FC.ADD_IDFA = False
FC.S2P = dict(FC.S2P)
FC.S2P.update({"screen_format": "long", "connectivity_type": "1"})

CAPTURED = []


def fake_send(url, p, blob, method="POST"):
    CAPTURED.append((url, method, p))
    return 200, b'{"fake":"offline"}'


def fake_mint(val, second, V=None, pid=None, tid=None, kind=None,
              max_steps=40_000_000):
    V = M.make_V(second) if V is None else V
    pid = M.DEFAULT_PID if pid is None else pid
    d0, d2, d4 = M.resolve_region(V, pid, M.DEFAULT_TID, None)
    descs, meta = M.build_descriptors(val, kind, d0, d2, d4)
    return b"\x00" * 192, {"status": "STUB", "steps": 0,
                           "desc10_padded": meta["desc10_padded"],
                           "desc10_unpadded": meta["desc10_unpadded"]}


M.mint_blob_ex = fake_mint
FC.send = fake_send

auid = str(uuid.uuid4())
t_track = time.time()
ins = FC.fmt(int(t_track) + 217, 431)

M.api_session_mint(GPS, auid, ins)
M.api_sdk_click_mint(GPS, auid, REFERRER, int(t_track), t_track + 210, ins)
FC.api_attribution(GPS, auid, "pt-" + auid[:8])

MOTO = {"session": 360, "sdk_click": 391, "attribution": 246}
MOTO_PARAMS = {"session": 43, "sdk_click": 47, "attribution": 22}
# this device has a SIM, so mcc/mnc legitimately ride on session + sdk_click
SIM_PARAMS = {"session": 2, "sdk_click": 2, "attribution": 0}
KIND = {"session": "session", "sdk_click": "click", "attribution": "attribution"}

print("=== ARM D PRE-FLIGHT (offline, no click, no GAID spent) ===")
print("GAID reused : %s" % GPS)
print("referrer len: %d" % len(REFERRER))
print()
ok = True
for url, method, p in CAPTURED:
    ep = url.split("?")[0].rsplit("/", 1)[-1]
    kind = KIND[ep]
    val = M.claims_from_wire(p, kind)
    _pad, n = M.claims_for_law(val, kind)
    want = MOTO_PARAMS[ep] + SIM_PARAMS[ep]
    good = len(p) == want
    ok = ok and good
    print("--- %s (%s) ---" % (ep.upper(), method))
    print("  params        : %d   (expect %d = moto %d + SIM %d)  %s"
          % (len(p), want, MOTO_PARAMS[ep], SIM_PARAMS[ep],
             "OK" if good else "MISMATCH"))
    print("  #10 claim     : %d B   (moto device %d, delta %+d)"
          % (n, MOTO[ep], n - MOTO[ep]))
    for k in ("mcc", "mnc", "api_level", "os_version", "device_name",
              "device_manufacturer", "hardware_name", "os_build", "language",
              "display_width", "display_height", "screen_density"):
        if k in p:
            print("  %-20s = %s" % (k, p[k]))
    for k in ("referrer", "click_time", "installed_at", "updated_at"):
        if k in p:
            print("  %-20s = %s" % (k, str(p[k])[:80]))
    if "created_at" in p:
        print("  %-20s = %s" % ("created_at", p["created_at"]))
    print()
print("param-count check: %s" % ("PASS" if ok else "FAIL"))
