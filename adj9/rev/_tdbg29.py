"""_tdbg29.py — death of taint: between step 333570 and 3.6M, log every BL/alu
event involving a seed-carrying node; report the LAST ones.  NEW file.
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

EVENTS = []
_orig_apply = tn._apply


def apply(pend):
    r = _orig_apply(pend)
    kind, extra, pc = pend
    if ex.steps < 3700000:
        if kind == "BL":
            for op in extra:
                nd = None
                if op[0] == "qpush":
                    nd = op[2]
                elif op[0] == "emit":
                    nd = op[3]
                if nd is not None and T.has_seed(nd):
                    EVENTS.append((ex.steps, hex(pc), op[0], str(nd)[:70]))
        elif kind == "alu":
            m, o = extra
            dest, specs = T.parse_alu(pc, m, o)
            if dest:
                kids = [tn.kid(sp, ex, pc) for sp in specs]
                if any(T.has_seed(k) for k in kids):
                    EVENTS.append((ex.steps, hex(pc), m, o,
                                   str(tn.R.get(T.canon(dest)))[:70]))
    return r


class StopRun(Exception):
    pass


def hook(e=None):
    e = e if e is not None else ex
    if e.steps > 3600000:
        raise StopRun()
    return tn.hook(e)


ex.__dict__["_step_hook"] = hook
try:
    st = ex.run(max_steps=60_000_000)
except StopRun:
    st = "stopped-by-debugger"
print("stopped at step %d (%s); seed events: %d" % (ex.steps, st, len(EVENTS)),
      flush=True)
for e in EVENTS[-25:]:
    print("  ", e, flush=True)
