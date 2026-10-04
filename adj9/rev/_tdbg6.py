"""_tdbg6.py — find the write history of MAIN slots 341..345 (body words 4..8)
and trace the instruction window around the final write of slot 341.
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
MAIN = 0x5450001000 & 0xFFFFF

for slot in (337, 341, 342, 345):
    wr = [h for h in HIST if h[1] == MAIN and h[3] == slot]
    print("slot MAIN.offs[%d]: %d writes" % (slot, len(wr)), flush=True)
    for s, sv, top, n, v, nd in wr[-4:]:
        print("   step=%d top=%s v=%08x nd=%s"
              % (s, top, v, str(nd)[:130]), flush=True)

# trace window around the last write of slot 341
wr341 = [h for h in HIST if h[1] == MAIN and h[3] == 341]
s_last = wr341[-1][0]
print("tracing window around step %d" % s_last, flush=True)
ex2 = T.TaintEx(second, descs, seednames=T.default_seednames())
ex2.__dict__["_tracewin"] = (s_last - 400, s_last + 2)
st2 = ex2.run(max_steps=20_000_000)
for ent in ex2.__dict__["_twlog"][-260:]:
    print("  tw step=%d pc=%s %s %s" % (ent[0], hex(ent[1]), ent[2], ent[3]),
          flush=True)
