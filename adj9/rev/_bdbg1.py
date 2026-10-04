"""_bdbg1.py — where does seed provenance die in the taint run?

Runs vm_taint.run_taint on a corpus row with a wrapper hook that:
  * every CKPT steps, counts seedy nodes in R / mem / queues / streams
  * logs every EMIT to the sink stream (step, pc, n, v) and whether the
    emitted node is seedy
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import vm_taint as VT
from vm_taint import Taint, run_taint, corpus_row_descs, corpus_row, _seedy
from fin_vm2 import FinEx
from vm_final import INS, IDX

ROW = int(sys.argv[1]) if len(sys.argv) > 1 else 7
CKPT = int(sys.argv[2]) if len(sys.argv) > 2 else 250_000
MAXS = int(sys.argv[3]) if len(sys.argv) > 3 else 60_000_000

SINK = 0x5500000000

descs = corpus_row_descs(ROW)
second, cap = corpus_row(ROW)
ex = FinEx(second, descs)
tn = Taint(ex, VT.default_seednames())
ex.__dict__["_step_hook"] = tn.hook

last_ckpt = [0]
n_emit = [0]
n_emit_seedy = [0]
sink_emits = []


def probe(label):
    rs = sum(1 for nd in tn.R.values() if _seedy(nd))
    ms = sum(1 for nd in tn.mem.values() if _seedy(nd))
    qs = sum(1 for q in tn.q.values() for nd in q if _seedy(nd))
    ss = 0
    sdicts = 0
    for s in tn.s.values():
        sdicts += 1
        ss += sum(1 for nd in s.offs.values() if _seedy(nd))
    print("[%s step=%d] seedy: R=%d mem=%d/%d q=%d stream=%d/%d"
          % (label, ex.steps, rs, ms, len(tn.mem), qs, ss, sdicts),
          flush=True)


real_hook = tn.hook


def hook(ex_=None):
    if ex.steps - last_ckpt[0] >= CKPT:
        last_ckpt[0] = ex.steps
        probe("ckpt")
    real_hook(ex_)


ex.__dict__["_step_hook"] = hook
t0 = time.time()
st = ex.run(max_steps=MAXS)
probe("end")
print("status=%s steps=%d nrand=%d %.0fs" % (st, ex.steps, ex.nrand,
                                             time.time() - t0), flush=True)

# the blob words: last emit per (sva,n) on SINK
last = {}
for (sva, n, v) in ex.emit_trace:
    last[(sva, n)] = v
words = [last.get((SINK, k)) for k in range(48)]
tnodes = tn.s.get(SINK)
tnodes = tnodes.offs if tnodes else {}
for k in range(48):
    nd = tnodes.get(k)
    sd = sorted(VT.seed_set(nd)) if nd is not None else None
    print("w%-2d val=%08x node=%s seeds=%s" % (
        k, (words[k] or 0) & 0xFFFFFFFF,
        "none" if nd is None else nd[0],
        (",".join(sd) if sd else "-") if sd is not None else "-"),
        flush=True)
