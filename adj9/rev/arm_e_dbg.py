"""Debug: why are arm_e session/click claims 6B longer than the device's?"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import arm_e_freshmint as E
import mint_pipeline as M
import adj9_full_chain as FC

t_click = time.time() - 400
ins = E.FC.fmt(int(t_click) + int(E.CTIT_INSTALL), 431)
gps = "00000000-1111-4222-8333-444444444444"
auid = "55555555-6666-4777-8888-999999999999"

# my params
p_mine = E.session_params(gps, auid, ins, int(time.time()) + 60)

# the ARM C path's params (api_session_mint's construction, minus the send)
sec = int(time.time()) + FC.MINT_SKEW
p_armc = dict(FC.S1P)
p_armc.update({"gps_adid": gps, "android_uuid": auid,
               "created_at": FC.fmt(sec - 1, 928).decode(),
               "sent_at": FC.fmt(sec - 1, 942).decode(),
               "installed_at": ins, "updated_at": ins})
p_armc.update(FC.DEV)
for k in ("no_sim", "mcc", "mnc", "install_version"):
    p_armc.pop(k, None)

ka = set(p_mine)
kb = set(p_armc)
print("only mine:", sorted(ka - kb))
print("only armc:", sorted(kb - ka))
for k in sorted(ka & kb):
    a, b = p_mine[k], p_armc[k]
    if a != b:
        print("diff %-28s mine=%r armc=%r" % (k, a, b))

va = M.claims_from_wire(p_mine, "session")
vb = M.claims_from_wire(p_armc, "session")
for k in sorted(set(va) | set(vb)):
    a, b = va.get(k), vb.get(k)
    if a != b:
        print("claim diff %-24s mine=%r armc=%r" % (k, a, b))
