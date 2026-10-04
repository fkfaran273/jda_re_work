"""_tdbg30.py - clean taint census with counters.  NEW file."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(400000)

import vm_taint as T

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.FinEx(second, descs)
tn = T.Taint(ex, T.default_seednames())

CNT = {}
SEEDHIT = {}
LAST = []
_oa = tn._apply


def apply(pend):
    r = _oa(pend)
    kind, extra, pc = pend
    CNT[kind] = CNT.get(kind, 0) + 1
    if kind == "BL":
        for op in extra:
            nd = op[2] if op[0] == "qpush" else (op[3] if op[0] == "emit"
                                                 else None)
            if nd is not None and T.has_seed(nd):
                SEEDHIT[op[0]] = SEEDHIT.get(op[0], 0) + 1
                if len(LAST) < 14:
                    LAST.append((ex.steps, hex(pc), op[0], str(nd)[:70]))
    elif kind == "alu":
        m, o = extra
        dest, specs = T.parse_alu(pc, m, o)
        if dest:
            kids = [tn.kid(sp, ex, pc) for sp in specs]
            if any(T.has_seed(k) for k in kids):
                SEEDHIT["alu"] = SEEDHIT.get("alu", 0) + 1
                if len(LAST) < 14:
                    LAST.append((ex.steps, hex(pc), m, o,
                                 str(tn.R.get(T.canon(dest)))[:70]))
    return r


tn._apply = apply


class StopRun(Exception):
    pass


_oh = tn.hook


def hook(e=None):
    e = e if e is not None else ex
    if e.steps > 1000000:
        raise StopRun()
    return _oh(e)


ex.__dict__["_step_hook"] = hook
try:
    ex.run(max_steps=60_000_000)
except StopRun:
    pass
print("counts:", CNT, flush=True)
print("seed hits:", SEEDHIT, flush=True)
for e in LAST:
    print("  ", e, flush=True)
