"""Debug2: device SAZ params vs arm_e params -> per-key claim lengths."""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import arm_e_freshmint as E
import mint_pipeline as M
from desc10_law import build_desc10, desc10_keys

t_click = time.time() - 400
ins = E.FC.fmt(int(t_click) + int(E.CTIT_INSTALL), 431)
gps = "00000000-1111-4222-8333-444444444444"
auid = "55555555-6666-4777-8888-999999999999"

saz = json.load(open(os.path.join(HERE, "saz_params.json")))

for skey, kind in (("session", "session"), ("sdk_click", "click"),
                   ("attribution", "attribution")):
    dev_p = saz[skey]
    if skey == "session":
        my_p = E.session_params(gps, auid, ins, int(time.time()) + 60)
    elif skey == "sdk_click":
        my_p = E.click_params(gps, auid, E.PLAY_REFERRER, t_click,
                              t_click + E.CTIT_BEGIN, ins,
                              int(time.time()) + 63)
    else:
        my_p = E.attr_params(gps, auid, int(time.time()) + 70)
    va = M.claims_from_wire(dev_p, kind)
    vb = M.claims_from_wire(my_p, kind)
    da = build_desc10(va, kind)
    db = build_desc10(vb, kind)
    print("%-11s device_claim=%dB  mine=%dB  delta=%+d"
          % (kind, len(da.rstrip("\x00")), len(db.rstrip("\x00")),
             len(db.rstrip("\x00")) - len(da.rstrip("\x00"))))
    for k in sorted(set(va) | set(vb)):
        a, b = va.get(k), vb.get(k)
        la, lb = len(str(a or "")), len(str(b or ""))
        if la != lb or a != b:
            print("   %-26s dev=%r(%d) mine=%r(%d)"
                  % (k, str(a)[:44], la, str(b)[:44], lb))
