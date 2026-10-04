import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE); sys.path.insert(0, REV); sys.path.insert(0, os.path.join(REV, "creditsea"))
import testbed as TB, desc10_58 as LAW, vm_final as V
import fin_vm2_fast as FFF
from fin_vm2_fast import FinEx, prepare
prepare()
s = TB.mine_log()[0]
dec = TB.decode(s["blob"]); d0, d4, d2, _p = TB.region_parts(dec, s["second"])
raw, _ = LAW.claims_for_law_58(s["val"], "session")
descs = TB.build_descs(s["second"], raw, d0, d4, d2)
ex = FinEx(int(s["second"]), descs)
st = ex.run()
bad = ex.__dict__.get("_bad_pc")
print("status", st, "steps", ex.steps, "bad_pc", hex(bad or 0))
k = V.IDX.get(bad)
print("bad pc in IDX:", k is not None)
if k is not None:
    m, ops, npc = V.FAST[k]
    print("  ins:", hex(bad), m, ops, "-> npc", hex(npc))
    kn = V.IDX.get(npc)
    print("  npc in IDX:", kn is not None, (V.FAST[kn] if kn is not None else ""))
PCADDR, BL = FFF.PCADDR, FFF.BL
starts = set(PCADDR[a] for a, _ in BL)
print("npc is block start:", npc in starts)
for (a, b) in BL:
    if PCADDR[a] <= bad < PCADDR[b - 1]:
        print("containing block %08x..%08x" % (PCADDR[a], PCADDR[b - 1]))
        break
