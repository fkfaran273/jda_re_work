"""trace_cmp.py — find the first pc where the fast interpreter diverges."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(HERE))
for p in (HERE, REV, os.path.join(REV, "creditsea")):
    if p not in sys.path:
        sys.path.insert(0, p)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 300000
import vmgen as G
import fin_vm2, fin_vm2_fast as FF
import testbed as TB, desc10_58 as LAW
import vm_final as V

s = TB.mine_log()[0]
dec = TB.decode(s["blob"]); d0, d4, d2, _p = TB.region_parts(dec, s["second"])
raw, _ = LAW.claims_for_law_58(s["val"], "session")
descs = TB.build_descs(s["second"], raw, d0, d4, d2)

ref = []
class RefProbe(fin_vm2.FinEx):
    def run(self, max_steps=4_000_000):
        self.__dict__["_step_hook"] = lambda e: ref.append(e.pc)
        try:
            return fin_vm2.FinEx.run(self, max_steps=max_steps)
        finally:
            self.__dict__.pop("_step_hook", None)
RefProbe(int(s["second"]), descs).run(max_steps=N)
print("ref steps captured:", len(ref))

# fast, traced build (compiled to a separate cache file)
G.TRACE = True
t, sig = G.load_tables()
bl, codes, ngen, _c = G.compile_blocks(t["FAST"], t["PC"], sig + "-tr")
FF.BL, FF.CODES, FF.PCADDR = bl, codes, t["PC"]
T = []
ex3 = FF.FinEx(int(s["second"]), descs)
ex3.__dict__["_T"] = T
ex3.run(max_steps=N)
print("fast steps captured:", len(T))
n = min(len(ref), len(T))
bad = None
for i in range(n):
    if ref[i] != T[i]:
        bad = i
        break
if bad is None:
    print("no divergence in first %d steps" % n)
else:
    print("DIVERGE at step %d" % bad)
    for i in range(max(0, bad - 12), min(bad + 3, n)):
        k = V.IDX.get(ref[i])
        m, ops, npc = V.FAST[k] if k is not None else ("?", "?", 0)
        print("  %8d ref=%08x %-8s %-38s | fast=%08x%s"
              % (i, ref[i], m, ops, T[i], " <<<<" if i == bad else ""))
