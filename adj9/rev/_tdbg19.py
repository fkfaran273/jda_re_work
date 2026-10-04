"""_tdbg19.py — register-write trace around step 3508275 (origin push of the
S-dependent value 0x9e).  NEW file.
"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(300000)

import vm_taint as T
import vm_final as V

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.TaintEx(second, descs, seednames=T.default_seednames())

W0, W1 = 3508180, 3508280
EV = []
_osr = T.TaintEx.set_reg


def set_reg(self, name, val, node):
    r = _osr(self, name, val, node)
    if W0 <= self.steps <= W1:
        EV.append((self.steps, self.pc, name, val, node))
    return r


T.TaintEx.set_reg = set_reg
st = ex.run(max_steps=20_000_000)
print("status=%s" % st, flush=True)
prev = None
for s, pc, name, val, node in EV:
    k = V.IDX.get(pc)
    m, ops, _ = V.FAST[k] if k is not None else ("?", "?", 0)
    tag = "" if prev == s else "\n"
    prev = s
    print("%s  step=%d pc=%s %s %s" % (tag, s, hex(pc), m, ops), flush=True)
    print("      %-4s = %08x nd=%s" % (name, val & T.M32, str(node)[:150]),
          flush=True)
