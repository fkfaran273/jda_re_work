"""_tdbg.py — diagnose where vm_taint loses provenance (fast, O(1) per op).

Logs the FIRST few stream EMIT/LENQ whose node is non-constant (node[0]!='k')
and counts totals, plus per-seed first-appearance.  NEW file.
"""
import os, sys, json, struct, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(200000)

import vm_taint as T

LOG = {"emit_nc": 0, "lenq_nc": 0, "emit_first": [], "lenq_first": [],
       "emit_last": [], "lenq_last": []}
STEP = [0]

_orig_emit = T.TaintStream.emit_t
_orig_lenq = T.TaintStream.lenq_t
NKEEP = 14


def emit_t(self, n, v, node):
    r = _orig_emit(self, n, v, node)
    if node[0] != "k":
        LOG["emit_nc"] += 1
        ent = (STEP[0], self.va, n & 0xFFFFFFFF, v & 0xFFFFFFFF,
               node[0], len(node))
        if len(LOG["emit_first"]) < NKEEP:
            LOG["emit_first"].append(ent)
        LOG["emit_last"] = (LOG["emit_last"] + [ent])[-NKEEP:]
    return r


def lenq_t(self, n):
    v, nd = _orig_lenq(self, n)
    if nd[0] != "k":
        LOG["lenq_nc"] += 1
        ent = (STEP[0], self.va, n & 0xFFFFFFFF, v & 0xFFFFFFFF, nd[0], len(nd))
        if len(LOG["lenq_first"]) < NKEEP:
            LOG["lenq_first"].append(ent)
        LOG["lenq_last"] = (LOG["lenq_last"] + [ent])[-NKEEP:]
    return v, nd


T.TaintStream.emit_t = emit_t
T.TaintStream.lenq_t = lenq_t


def probe(e):
    STEP[0] = e.steps


descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.TaintEx(second, descs, seednames=T.default_seednames())
ex.__dict__["_probe"] = (65536, probe)
t0 = time.time()
st = ex.run(max_steps=20_000_000)
STEP[0] = ex.steps
print("status=%s steps=%d healed=%d %.0fs" % (st, ex.steps, ex.healed,
                                              time.time() - t0), flush=True)
print("non-const EMITs: %d   non-const LENQs: %d" % (LOG["emit_nc"], LOG["lenq_nc"]))
for tag in ("emit", "lenq"):
    for lst in (LOG[tag + "_first"], LOG[tag + "_last"]):
        for e in lst:
            print("  %s step=%9d s=%x n=%6d v=%08x nd0=%s nargs=%d"
                  % ((tag,) + e), flush=True)
blob, stream = T.blob_from_ex(ex, second)
print("blob_match=%s stream=0x%x" % (blob == cap, stream or 0), flush=True)
nodes = T.word_nodes(ex, stream)
for i in range(48):
    nd = nodes.get(i)
    print("w%-2d %s" % (i, (T.fmt(nd, seen=set())[:120] if nd is not None
                            else "<none>")), flush=True)
