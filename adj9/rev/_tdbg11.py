"""_tdbg11.py — instruction + register-node trace around step 3823739 where a
K node carries an S-dependent value.  NEW file.
"""
import os, sys, json, struct, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(200000)

import vm_taint as T
import vm_final as V

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.TaintEx(second, descs, seednames=T.default_seednames())

W0, W1 = 3823400, 3823760
LOGSN = []          # setnode events
_orig_setnode = T.TaintEx.setnode


def setnode(self, name, nd):
    r = _orig_setnode(self, name, nd)
    if W0 <= self.steps <= W1:
        LOGSN.append((self.steps, self.pc, name, self.R.get(name, 0), nd))
    return r


T.TaintEx.setnode = setnode
ex.__dict__["_tracewin"] = (W0, W1)
st = ex.run(max_steps=20_000_000)
print("status=%s" % st, flush=True)
tw = ex.__dict__["_twlog"]
print("trace events: %d, setnode events: %d" % (len(tw), len(LOGSN)), flush=True)
sn_by_step = {}
for s, pc, name, val, nd in LOGSN:
    sn_by_step.setdefault(s, []).append((pc, name, val, nd))
for s, pc, m, ops in tw:
    print("  step=%d pc=%s %s %s" % (s, hex(pc), m, ops), flush=True)
    for pc2, name, val, nd in sn_by_step.get(s, []):
        print("        -> %-4s = %08x  nd=%s" % (name, val & 0xFFFFFFFF,
                                                 str(nd)[:90]), flush=True)
