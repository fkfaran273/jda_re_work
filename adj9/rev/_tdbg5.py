"""_tdbg5.py — RAW nodes at the workhorse: LENQ reads and EMIT writes near the
end of the run, for the MAIN workspace and the SINK stream.
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

LQ, EM = [], []
_orig_lenq = T.TaintStream.lenq_t
_orig_emit = T.TaintStream.emit_t


def lenq_t(self, n):
    v, nd = _orig_lenq(self, n)
    if ex.steps > 9_870_000:
        LQ.append((ex.steps, self.va & 0xFFFFF, self.top[-1],
                   n & 0xFFFFFFFF, v & 0xFFFFFFFF, nd))
    return v, nd


def emit_t(self, n, v, node):
    r = _orig_emit(self, n, v, node)
    if ex.steps > 9_870_000:
        EM.append((ex.steps, self.va & 0xFFFFF, self.top[-1],
                   n & 0xFFFFFFFF, v & 0xFFFFFFFF, node))
    return r


T.TaintStream.lenq_t = lenq_t
T.TaintStream.emit_t = emit_t
st = ex.run(max_steps=20_000_000)
T.TaintStream.lenq_t = _orig_lenq
T.TaintStream.emit_t = _orig_emit
print("status=%s" % st, flush=True)
blob, stream = T.blob_from_ex(ex, second)
print("blob_match=%s" % (blob == cap), flush=True)
MAIN = 0x5450001000 & 0xFFFFF
SINK = 0x5500000000 & 0xFFFFF
print("--- LENQs after 9.87M (raw node) ---")
for s, sv, top, n, v, nd in LQ[:60]:
    print("  step=%d s=%05x top=%s n=%d v=%08x nd=%s"
          % (s, sv, top, n, v, str(nd)[:110]), flush=True)
print("--- EMITs after 9.87M (raw node) ---")
for s, sv, top, n, v, nd in EM[:40]:
    print("  step=%d s=%05x top=%s n=%d v=%08x nd=%s"
          % (s, sv, top, n, v, str(nd)[:110]), flush=True)
