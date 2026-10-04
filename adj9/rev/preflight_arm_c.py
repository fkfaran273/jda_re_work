"""preflight_arm_c.py — OFFLINE dry run of arm_c's exact param path.

Stubs out only two things: the Unicorn mint (slow) and the network send.
Everything else is the real code, so the claim strings and #10 lengths are
exactly what a live run would produce. Target: session 360, click 391.
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

PROFILE = json.load(open(os.path.join(HERE, "moto_g42_profile.json")))
FC.DEV = dict(PROFILE["DEV"])
FC.UA = PROFILE["UA"]
FC.OFF_MINUTES, FC.OFF_LABEL = PROFILE["OFF_MINUTES"], PROFILE["OFF_LABEL"]
FC.ADD_IDFA = PROFILE["ADD_IDFA"]

CAPTURED = []


def fake_send(url, p, blob, method="POST"):
    CAPTURED.append((url, method, p))
    return 200, b'{"fake":"offline"}'


def fake_mint(val, second, V=None, pid=None, tid=None, kind=None,
              max_steps=40_000_000):
    V = M.make_V(second) if V is None else V
    pid = os.getpid() if pid is None else pid
    d0, d2, d4 = M.resolve_region(V, pid, tid or 0, None)
    descs, meta = M.build_descriptors(val, kind, d0, d2, d4)
    n10 = meta["desc10_unpadded"]
    info = {"status": "STUB", "steps": 0, "desc10_padded": n10,
            "desc10_unpadded": n10, "region_src": "F.py [REAL]",
            "V": V, "pid": pid}
    return b"\x00" * 192, info


M.mint_blob_ex = fake_mint
FC.send = fake_send

gps = str(uuid.uuid4())
auid = str(uuid.uuid4())
t_track = time.time()
ins = FC.fmt(int(t_track) + 217, 431)
ref = "utm_source=(not%20set)&utm_medium=(not%20set)"

M.api_session_mint(gps, auid, ins)
M.api_sdk_click_mint(gps, auid, ref, int(t_track), t_track + 210, ins)

TARGET = {"session": 360, "sdk_click": 391}
KINDNAME = {"session": "session", "sdk_click": "click"}


def check():
    ok = True
    for url, method, p in CAPTURED:
        ep = url.rsplit("/", 1)[-1]
        kind = KINDNAME[ep]
        val = M.claims_from_wire(p, kind)
        _padded, nclaim = M.claims_for_law(val, kind)
        want = TARGET[ep]
        good = nclaim == want
        ok = ok and good
        print("=== %s (%s) ===" % (ep.upper(), method))
        print("  params sent      : %d" % len(p))
        print("  #10 claim length : %d  (device %d)  %s"
              % (nclaim, want, "OK" if good else "MISMATCH"))
        print("  mcc/mnc present  : %s / %s"
              % ("mcc" in p, "mnc" in p))
        print("  install_version  : %s" % ("install_version" in p))
        for k in ("api_level", "os_version", "device_name", "language",
                  "installed_at", "click_time", "install_begin_time"):
            if k in p:
                print("  %-18s: %s" % (k, p[k]))
        print()
    return ok


if __name__ == "__main__":
    ok = check()
    print("PRE-FLIGHT: %s" % ("PASS" if ok else "FAIL"))
    sys.exit(0 if ok else 1)
