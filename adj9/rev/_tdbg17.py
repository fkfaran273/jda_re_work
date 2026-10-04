"""_tdbg17.py — invariant check: every register write / queue push must carry
a node whose val_of matches the value.  Log the first violations with pc.
NEW file.
"""
import os, sys, struct, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(300000)

import vm_taint as T
import vm_final as V

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.TaintEx(second, descs, seednames=T.default_seednames())

VIOL = []
CURPC = [0]

_orig_sr = T.TaintEx.set_reg


def set_reg(self, name, val, node):
    r = _orig_sr(self, name, val, node)
    if len(VIOL) < 40 and name not in ("wzr", "xzr"):
        want = val & T.M32 if name.startswith("w") else val & T.M64
        got = T.val_of(node) & (T.M32 if name.startswith("w") else T.M64)
        if want != got:
            VIOL.append(("reg", self.pc, name, val & T.M64,
                         T.val_of(node), str(node)[:150]))
            CURPC[0] = self.pc
    return r


T.TaintEx.set_reg = set_reg
st = ex.run(max_steps=20_000_000)
print("status=%s steps=%d violations=%d" % (st, ex.steps, len(VIOL)),
      flush=True)
for kind, pc, name, val, got, nd in VIOL[:20]:
    k = V.IDX.get(pc)
    m, ops, _ = V.FAST[k] if k is not None else ("?", "?", 0)
    print("  %s pc=%s (%s %s) reg=%s val=%016x nodeval=%016x nd=%s"
          % (kind, hex(pc), m, ops, name, val, got, nd), flush=True)
