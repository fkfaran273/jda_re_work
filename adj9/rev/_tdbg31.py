"""_tdbg31.py - incremental-seedy census: find the LAST seed-carrying event
and the first all-constant chain op.  NEW file."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(400000)

import vm_taint as T

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.FinEx(second, descs)
tn = T.Taint(ex, T.default_seednames())

SEEDY = {}


def seedy(nd):
    if nd is None:
        return False
    v = SEEDY.get(id(nd))
    if v is not None:
        return v
    if nd[0] == "s":
        v = True
    elif nd[0] in ("k", "rnd"):
        v = False
    else:
        v = any(seedy(c) for c in T._kids(nd))
    SEEDY[id(nd)] = v
    return v


LAST = []
FIRSTK = []
_oa = tn._apply


def apply(pend):
    r = _oa(pend)
    kind, extra, pc = pend
    if kind == "BL":
        for op in extra:
            if op[0] == "qpush":
                if seedy(op[2]):
                    LAST.append((ex.steps, hex(pc), "qpush", str(op[2])[:80]))
                else:
                    FIRSTK.append((ex.steps, hex(pc), "qpush-k", str(op[2])[:40]))
            elif op[0] == "emit":
                if seedy(op[3]):
                    LAST.append((ex.steps, hex(pc), "emit", str(op[3])[:80]))
    elif kind == "alu":
        m, o = extra
        dest, specs = T.parse_alu(pc, m, o)
        if dest:
            kids = [tn.kid(sp, ex, pc) for sp in specs]
            nd = tn.R.get(T.canon(dest))
            if nd is not None:
                SEEDY[id(nd)] = any(seedy(k) for k in kids)
    elif kind == "csel":
        pass
    del FIRSTK[600:]
    del LAST[400:]
    return r


tn._apply = apply


class StopRun(Exception):
    pass


_oh = tn.hook


def hook(e=None):
    e = e if e is not None else ex
    if e.steps > 4200000:
        raise StopRun()
    return _oh(e)


ex.__dict__["_step_hook"] = hook
try:
    ex.run(max_steps=60_000_000)
except StopRun:
    pass
print("last seed events:", flush=True)
for e in LAST[-14:]:
    print("  ", e, flush=True)
print("first k-only pushes (after step 3.3M):", flush=True)
n = 0
for e in FIRSTK:
    if e[0] > 3300000 and n < 14:
        print("  ", e, flush=True)
        n += 1
