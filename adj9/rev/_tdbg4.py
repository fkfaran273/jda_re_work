"""_tdbg4.py — emit history of the body slots: who last wrote w4..w47, with
what node, and a trace window around the first body-word write.
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
_orig_pushs = T.FinStream.pushs
_orig_pops = T.FinStream.pops


def emit_t(self, n, v, node):
    r = _orig_emit(self, n, v, node)
    HIST.append((ex.steps, self.va & 0xFFFFF, self.top[-1], n & 0xFFFFFFFF,
                 v & 0xFFFFFFFF, node))
    return r


def pushs(self):
    r = _orig_pushs(self)
    HIST.append((ex.steps, self.va & 0xFFFFF, "PUSHS", self.acc, len(self.top),
                 None))
    return r


def pops(self):
    r = _orig_pops(self)
    HIST.append((ex.steps, self.va & 0xFFFFF, "POPS", self.acc, len(self.top),
                 None))
    return r


T.TaintStream.emit_t = emit_t
T.FinStream.pushs = pushs
T.FinStream.pops = pops

t0 = time.time()
st = ex.run(max_steps=20_000_000)
T.TaintStream.emit_t = _orig_emit
T.FinStream.pushs = _orig_pushs
T.FinStream.pops = _orig_pops
print("status=%s steps=%d %.0fs emits=%d" % (st, ex.steps, time.time() - t0,
                                             len(HIST)), flush=True)
blob, stream = T.blob_from_ex(ex, second)
w = struct.unpack(">48I", blob)
print("blob_match=%s stream=%05x" % (blob == cap, stream & 0xFFFFF), flush=True)

# reconstruct: for stream 0x5450001000 (workspace MAIN) find writes of the body
# values.  The workhorse read slots idx; we know final values w[0..47].  Find
# ALL emits on 0x5450001000 whose value == w[j] (last 60 emits before end).
MAIN = 0x5450001000 & 0xFFFFF
SINK = 0x5500000000 & 0xFFFFF

# The final emit per blob word j on the SINK stream:
for j in (0, 1, 2, 3, 4, 5, 8, 47):
    ent = [h for h in HIST if h[1] == SINK and h[3] == j and h[4] == w[j]]
    if not ent:
        print("w%-2d: NO sink emit with value" % j)
        continue
    s, sv, top, n, v, nd = ent[-1]
    print("w%-2d final sink emit step=%d top=%s n=%d v=%08x node=%s"
          % (j, s, top, n, v, (T.fmt(nd, seen=set())[:90] if nd is not None
                               else "?")), flush=True)

# stream MAIN: last 40 emit records before the workhorse (step>9.0M)
tail = [h for h in HIST if h[1] == MAIN and h[0] > 9_000_000
        and h[2] != "PUSHS" and h[2] != "POPS"]
print("MAIN emits after step 9.0M: %d" % len(tail), flush=True)
for h in tail[:24]:
    s, sv, top, n, v, nd = h
    print("  MAIN step=%d top=%s n=%d v=%08x node=%s"
          % (s, top, n, v, (T.fmt(nd, seen=set())[:90] if nd is not None
                            else "?")), flush=True)
tail2 = [h for h in HIST if h[1] == MAIN and h[2] in ("PUSHS", "POPS")]
print("MAIN PUSHS/POPS: %d" % len(tail2), flush=True)
for h in tail2[-12:]:
    print("  MAIN %s step=%d acc=%s ntop=%s" % (h[2], h[0], h[3], h[4]),
          flush=True)
