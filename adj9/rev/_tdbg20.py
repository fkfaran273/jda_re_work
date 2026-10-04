"""_tdbg20.py — birth tracebacks of the K nodes on the whitening chain:
K(158), K(66), K(220), K(186) — the first time each ('k', v) is interned,
with the executor pc and python call site.  NEW file.
"""
import os, sys, struct, traceback
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(300000)

import vm_taint as T
import vm_final as V

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
TARGETS = {158, 66, 220, 186, 203, 85, 63, 106}
BIRTH = {}

_mk = T.mk
EX = [None]


def mk(*a):
    r = _mk(*a)
    if a[0] == "k" and a[1] in TARGETS and a[1] not in BIRTH:
        st = traceback.extract_stack(limit=5)
        pc = EX[0].pc if EX[0] is not None else 0
        BIRTH[a[1]] = (pc, [(f.filename.split('_')[-1], f.lineno, f.name)
                            for f in st[-4:-1]])
    return r


T.mk = mk
ex = T.TaintEx(second, descs, seednames=T.default_seednames())
EX[0] = ex
st = ex.run(max_steps=20_000_000)
print("status=%s births=%d" % (st, len(BIRTH)), flush=True)
for v in sorted(BIRTH):
    pc, frames = BIRTH[v]
    k = V.IDX.get(pc)
    m, ops, _ = V.FAST[k] if k is not None else ("?", "?", 0)
    print("K(%d): first born at pc=%s (%s %s)" % (v, hex(pc), m, ops),
          flush=True)
    for fn, ln, name in frames:
        print("    %s:%d %s" % (fn, ln, name), flush=True)
