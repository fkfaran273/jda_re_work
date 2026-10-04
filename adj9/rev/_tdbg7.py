"""_tdbg7.py — find the FIRST emit anywhere of each body word's final value,
then trace the instruction window around the first occurrence of w4's value.
NEW file.
"""
import os, sys, json, struct, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(200000)

import vm_taint as T

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.TaintEx(second, descs, seednames=T.default_seednames())

HIST = []
_orig_emit = T.TaintStream.emit_t


def emit_t(self, n, v, node):
    r = _orig_emit(self, n, v, node)
    HIST.append((ex.steps, self.va & 0xFFFFF, self.top[-1], n & 0xFFFFFFFF,
                 v & 0xFFFFFFFF, node))
    return r


T.TaintStream.emit_t = emit_t
st = ex.run(max_steps=20_000_000)
T.TaintStream.emit_t = _orig_emit
print("status=%s steps=%d emits=%d" % (st, ex.steps, len(HIST)), flush=True)
blob, stream = T.blob_from_ex(ex, second)
w = struct.unpack(">48I", blob)

for j in (4, 5, 8, 9, 20, 47):
    hits = [(k, h) for k, h in enumerate(HIST) if h[4] == w[j]]
    print("w%-2d v=%08x : %d occurrences; first 3:" % (j, w[j], len(hits)),
          flush=True)
    for k, h in hits[:3]:
        print("   hist#%d step=%d s=%05x top=%s n=%d nd=%s"
              % (k, h[0], h[1], h[2], h[3], str(h[5])[:120]), flush=True)

# trace around the first occurrence of w4's value
k0 = [k for k, h in enumerate(HIST) if h[4] == w[4]][0]
s0 = HIST[k0][0]
print("first w4 value emit at step %d" % s0, flush=True)
ex2 = T.TaintEx(second, descs, seednames=T.default_seednames())
ex2.__dict__["_tracewin"] = (s0 - 700, s0 + 2)
st2 = ex2.run(max_steps=20_000_000)
tw = ex2.__dict__["_twlog"]
print("trace %d instructions, printing non-copy-loop lines" % len(tw),
      flush=True)
# print only ALU/ldr/str lines (skip the repetitive loop skeleton)
from collections import Counter
pcs = Counter()
for ent in tw:
    pcs[ent[1]] += 1
skip = {pc for pc, c in pcs.items() if c > 8}   # loop skeleton
for s, pc, m, ops in tw:
    if pc in skip and m not in ("bl",):
        continue
    print("  tw step=%d pc=%s %s %s" % (s, hex(pc), m, ops), flush=True)
