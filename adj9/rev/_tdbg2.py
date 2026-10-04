"""_tdbg2.py — find the exact pc sites where vm_taint drops seed provenance.

Enables TaintEx's built-in _dropdet (setnode(K) while a seed-carrying node is
replaced, value unchanged) and reports the pc histogram + surrounding code.
NEW file.
"""
import os, sys, json, struct, time
from collections import Counter
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(200000)

import vm_taint as T
import vm_final as V

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.TaintEx(second, descs, seednames=T.default_seednames())
ex.__dict__["_dropdet"] = []
t0 = time.time()
st = ex.run(max_steps=20_000_000)
print("status=%s steps=%d healed=%d %.0fs" % (st, ex.steps, ex.healed,
                                              time.time() - t0), flush=True)
dd = ex.__dict__["_dropdet"]
print("drops: %d" % len(dd), flush=True)
pc_hist = Counter(hex(pc) for _, pc, _, _, _ in dd)
print("drop sites (pc):")
for pc, n in pc_hist.most_common(30):
    k = V.IDX.get(int(pc, 16))
    if k is not None:
        m, ops, npc = V.FAST[k]
        print("  pc=%s n=%5d  %s %s" % (pc, n, m, ops))
    else:
        print("  pc=%s n=%5d  <no insn>" % (pc, n))
# what do dropped nodes look like
kinds = Counter(nd[0] for *_, nd in dd)
print("dropped node kinds:", dict(kinds), flush=True)
# sample drops of each site
seen = {}
for step, pc, name, val, nd in dd:
    p = hex(pc)
    if seen.get(p, 0) < 2:
        seen[p] = seen.get(p, 0) + 1
        print("  sample pc=%s step=%d reg=%s val=%08x node=%s"
              % (p, step, name, val, T.fmt(nd, seen=set())[:160]), flush=True)
blob, stream = T.blob_from_ex(ex, second)
print("blob_match=%s" % (blob == cap), flush=True)
