"""_tdbg25.py — taint census: how many queue pushes / emits / lenqs carry
seed nodes, and where is the LAST seed-carrying event?  NEW file.
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

CENSUS = {"push_seed": 0, "push_k": 0, "emit_seed": 0, "emit_k": 0,
          "lenq_seed": 0, "lenq_k": 0, "last_seed_push": 0,
          "last_seed_emit": 0, "last_seed_lenq": 0}
_orig_apply = tn._apply


def apply(pend):
    r = _orig_apply(pend)
    kind, extra, pc = pend
    if kind == "BL":
        for op in extra:
            t = op[0]
            if t == "qpush":
                if T.has_seed(op[2]):
                    CENSUS["push_seed"] += 1
                    CENSUS["last_seed_push"] = ex.steps
                else:
                    CENSUS["push_k"] += 1
            elif t == "emit":
                if T.has_seed(op[3]):
                    CENSUS["emit_seed"] += 1
                    CENSUS["last_seed_emit"] = ex.steps
                else:
                    CENSUS["emit_k"] += 1
            elif t == "lenq":
                nd = tn.tstream(op[1]).offs.get((0 + op[2]) & T.M32)
                # node actually returned comes from the stream's top; recompute
                pass
    return r


tn._apply = apply
ex.__dict__["_step_hook"] = tn.hook
st = ex.run(max_steps=60_000_000)
if tn.pending is not None:
    tn._apply(tn.pending)
print("status=%s" % st, flush=True)
print(CENSUS, flush=True)
