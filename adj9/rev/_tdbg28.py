"""_tdbg28.py — queue-sync check: after each BL apply, compare my parallel
node-queue with ex.queues (lengths and per-slot value match).  Log first
mismatch.  NEW file.
"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(400000)

import vm_taint as T

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.FinEx(second, descs)
tn = T.Taint(ex, T.default_seednames())

MISMATCH = []
_orig_apply = tn._apply


def apply(pend):
    r = _orig_apply(pend)
    kind, extra, pc = pend
    if kind == "BL" and len(MISMATCH) < 5:
        for op in extra:
            if op[0] in ("qpush", "qpop", "capswap", "cappush"):
                qva = op[1]
                mine = tn.q.get(qva, [])
                real = ex.queues.get(qva, [])
                if len(mine) != len(real):
                    MISMATCH.append(("len", ex.steps, hex(pc), op[0],
                                     hex(qva), len(mine), len(real)))
                else:
                    for i, (mn, rv) in enumerate(zip(mine, real)):
                        v = rv[0] if isinstance(rv, tuple) else rv
                        # node value check for k-nodes only
                        if mn[0] == "k" and (mn[1] & T.M32) != (v & T.M32):
                            MISMATCH.append(("val", ex.steps, hex(pc), op[0],
                                             hex(qva), i, mn[1] & T.M32,
                                             v & T.M32))
                            break
                break
    return r


tn._apply = apply
ex.__dict__["_step_hook"] = tn.hook
st = ex.run(max_steps=60_000_000)
print("status=%s mismatches=%d" % (st, len(MISMATCH)), flush=True)
for m in MISMATCH[:5]:
    print("  ", m, flush=True)
