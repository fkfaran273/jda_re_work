"""_tdbg22.py — probe the v2 side band during header generation (the last
~200 instructions): log every apply's parse + resulting nodes.
NEW file.
"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(400000)

import vm_taint as T
import vm_final as V

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.FinEx(second, descs)
tn = T.Taint(ex, T.default_seednames())
LOG = []
_orig_apply = tn._apply
ARMB = [ex.nrand]  # start logging when the 7th rand fires


def apply(pend):
    r = _orig_apply(pend)
    if ex.nrand >= 7 and len(LOG) < 130:
        LOG.append((ex.steps, ex.pc, pend[0],
                    str(pend[1])[:110],
                    "w0=%s w2=%s w3=%s w21=%s" % (
                        str(tn.R.get("w0"))[:40], str(tn.R.get("w2"))[:40],
                        str(tn.R.get("w3"))[:40], str(tn.R.get("w21"))[:40])))
    return r


tn._apply = apply
ex.__dict__["_step_hook"] = tn.hook
st = ex.run(max_steps=60_000_000)
if tn.pending is not None:
    tn._apply(tn.pending)
print("status=%s" % st, flush=True)
for s, pc, kind, extra, regs in LOG[:110]:
    k = V.IDX.get(pc)
    m, ops, _ = V.FAST[k] if k is not None else ("?", "?", 0)
    print("step=%d pc=%s (%s %s) kind=%s %s\n     %s"
          % (s, hex(pc), m, ops, kind, extra, regs), flush=True)
