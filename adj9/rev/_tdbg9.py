"""_tdbg9.py — birth of the K leaf ('k', 0x1f36082c): hook mk()/K() and log
the first creation sites of the final body-word values (constant leaves).
NEW file.
"""
import os, sys, json, struct, time, traceback
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(200000)

import vm_taint as T

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
blob_true = cap
w_true = struct.unpack(">48I", blob_true)

BIRTHS = {}
TARGETS = {w_true[j] for j in (4, 5, 8, 47)}

_mk = T.mk


def mk(*a):
    r = _mk(*a)
    if a[0] == "k" and a[1] in TARGETS and a[1] not in BIRTHS:
        BIRTHS[a[1]] = (traceback.extract_stack(limit=6), CURSTEP[0])
    return r


T.mk = mk
CURSTEP = [0]

ex = T.TaintEx(second, descs, seednames=T.default_seednames())


def probe(e):
    CURSTEP[0] = e.steps


ex.__dict__["_probe"] = (1024, probe)
st = ex.run(max_steps=20_000_000)
print("status=%s births=%d" % (st, len(BIRTHS)), flush=True)
for v, (stk, step) in sorted(BIRTHS.items()):
    print("value %08x first born near step %d:" % (v, step), flush=True)
    for fr in stk[-4:]:
        print("   %s:%d in %s  %s" % (os.path.basename(fr.filename), fr.lineno,
                                      fr.name, fr.line[:80] if fr.line else ""),
              flush=True)
