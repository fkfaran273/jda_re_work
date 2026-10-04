"""_tdbg26.py — O(1) taint census: node-KIND histograms of queue pushes and
stream emits, in time buckets.  NEW file.
"""
import os, sys, struct
from collections import Counter
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(400000)

import vm_taint as T

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.FinEx(second, descs)
tn = T.Taint(ex, T.default_seednames())

PUSHK = Counter()
EMITK = Counter()
_last_seed_push = [0]
_last_seed_emit = [0]
_orig_apply = tn._apply


def apply(pend):
    r = _orig_apply(pend)
    kind, extra, pc = pend
    if kind == "BL":
        for op in extra:
            t = op[0]
            if t == "qpush":
                nd = op[2]
                PUSHK[nd[0]] += 1
                if nd[0] == "s":
                    _last_seed_push[0] = max(_last_seed_push[0], ex.steps)
            elif t == "emit":
                nd = op[3]
                EMITK[nd[0]] += 1
    return r


tn._apply = apply
ex.__dict__["_step_hook"] = tn.hook
st = ex.run(max_steps=60_000_000)
if tn.pending is not None:
    tn._apply(tn.pending)
print("status=%s" % st, flush=True)
print("push kinds:", dict(PUSHK), flush=True)
print("emit kinds:", dict(EMITK), flush=True)
# show a few seed-typed pushes
print("last raw-seed push step:", _last_seed_push[0], flush=True)
