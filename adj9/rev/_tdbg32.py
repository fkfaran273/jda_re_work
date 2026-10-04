"""_tdbg32.py - full-run census with O(1) seedy; find last seed event.  NEW."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(400000)
import vm_taint as T

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.FinEx(second, descs)
tn = T.Taint(ex, T.default_seednames())
HIT = []
_oa = tn._apply
def apply(pend):
    r = _oa(pend)
    kind, extra, pc = pend
    if kind == "BL":
        for op in extra:
            nd = op[2] if op[0] == "qpush" else (op[3] if op[0] == "emit" else None)
            if nd is not None and T._seedy(nd):
                HIT.append((ex.steps, hex(pc), op[0], nd))
    elif kind == "alu":
        m, o = extra
        dest, specs = T.parse_alu(pc, m, o)
        if dest:
            nd = tn.R.get(T.canon(dest))
            if nd is not None and T._seedy(nd):
                HIT.append((ex.steps, hex(pc), m, o, nd))
    if len(HIT) > 900:
        del HIT[:700]
    return r
tn._apply = apply
ex.__dict__["_step_hook"] = tn.hook
st = ex.run(max_steps=4300000)
if tn.pending is not None:
    tn._apply(tn.pending)
print("status=%s total tail hits shown" % st, flush=True)
for e in HIT[-30:]:
    print("  ", (e[0], e[1], e[2], e[3], str(e[4])[:110] if len(e) > 4 else ""),
          flush=True)
# final body word nodes
s0 = tn.s.get(0x5500000000)
for idx in (0, 1, 4, 8):
    if s0: print("sink[%d]=%s" % (idx, str(s0.offs.get(idx))[:80]), flush=True)
