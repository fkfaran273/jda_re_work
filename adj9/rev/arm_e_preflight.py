"""Offline preflight for arm_e_freshmint.py — no network."""
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import arm_e_freshmint as E
import mint_pipeline as M

t_click = time.time() - 400
ins = E.FC.fmt(int(t_click) + int(E.CTIT_INSTALL), 431)
tb = t_click + E.CTIT_BEGIN
gps = "00000000-1111-4222-8333-444444444444"
auid = "55555555-6666-4777-8888-999999999999"

d0 = b"\x00" * 144
d2 = b"\x00" * 4
d4 = b"\x00" * 32

for name, kind, p in (
        ("session", "session",
         E.session_params(gps, auid, ins, int(time.time()) + 60)),
        ("sdk_click", "click",
         E.click_params(gps, auid, E.PLAY_REFERRER, t_click, tb, ins,
                        int(time.time()) + 63)),
        ("attribution", "attribution",
         E.attr_params(gps, auid, int(time.time()) + 70))):
    val = M.claims_from_wire(p, kind)
    descs, meta = M.build_descriptors(val, kind, d0, d2, d4)
    print("%-11s params=%d claim10=%dB (padded %dB) claims=%d keys"
          % (name, len(p), meta["desc10_unpadded"], meta["desc10_padded"],
             len(val)))
    # spot-check the fresh stamps
    print("   created_at=%s sent_at=%s" % (p["created_at"], p["sent_at"]))

print("expect: 43/360, 47/391, 22/246 (device-exact)")
