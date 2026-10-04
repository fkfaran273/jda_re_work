"""_bdbg3.py — trace the final copy loop: which stream/indices feed the 48
blob words, and which earlier EMITs wrote those positions."""
import json
import os
import struct
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fin_vm2 import FinEx
from vm_taint import corpus_row_descs, corpus_row

ROW = int(sys.argv[1]) if len(sys.argv) > 1 else 7

descs = corpus_row_descs(ROW)
second, cap = corpus_row(ROW)
ex = FinEx(second, descs)
ex.__dict__["_emit_full"] = []
ex.__dict__["_lenq_log"] = []
t0 = time.time()
st = ex.run(max_steps=60_000_000)
print("status=%s steps=%d nrand=%d %.0fs" % (st, ex.steps, ex.nrand,
                                             time.time() - t0), flush=True)

ef = ex.__dict__["_emit_full"]
lq = ex.__dict__["_lenq_log"]

# 1. the 48 final-loop LENQs (pc == 0x117a00)
finalq = [e for e in lq if e[0] == 0x117a00]
print("final-loop LENQs:", len(finalq))
for e in finalq[:6]:
    print("  pc=%x sva=%x idx=%d top=%d val=%08x" % (e[0], e[1], e[2], e[3], e[4]))
src_svas = Counter(e[1] for e in finalq)
print("LENQ source streams:", {hex(k): v for k, v in src_svas.items()})
bases = Counter(e[3] for e in finalq)
print("LENQ tops:", {hex(k): v for k, v in bases.items()})
idxs = [(e[2], e[4]) for e in finalq]
print("first idx:", idxs[0] if idxs else None, "last idx:", idxs[-1] if idxs else None)
mono = all(idxs[i][0] + 1 == idxs[i + 1][0] for i in range(len(idxs) - 1))
print("indices monotonic +1:", mono)

# the blob words must equal these LENQ values
last = {}
for (sva, n, v) in ex.emit_trace:
    last[(sva, n)] = v & 0xFFFFFFFF
blob = [last.get((0x5500000000, k), 0) for k in range(48)]
same = all((blob[i] == idxs[i][1]) for i in range(min(48, len(idxs))))
print("final LENQ values == blob words:", same, "nlenq:", len(idxs))

# 2. which EMITs wrote those absolute positions of the source stream?
if finalq:
    sva = finalq[0][1]
    want = set(e[3] + e[2] for e in finalq)      # absolute = top + n
    base_abs = min(want)
    writers = {}
    for (pc, s, t, n, v) in ef:
        if s == sva:
            a = t + n
            if a in want:
                writers.setdefault(a, []).append((pc, t, n, v))
    print("\nwriters of the %d source positions (sva=%x abs %d..%d):"
          % (len(want), sva, base_abs, base_abs + 47))
    pcs = Counter()
    for a in sorted(want):
        wl = writers.get(a, [])
        for (pc, t, n, v) in wl:
            pcs[pc] += 1
    print("writer PCs:", {hex(k): v for k, v in pcs.items()})
    multi = sum(1 for a in want if len(writers.get(a, [])) > 1)
    print("positions written more than once:", multi)
    print("\nfinal writer per position:")
    for i in range(48):
        a = base_abs + i
        wl = writers.get(a, [])
        if not wl:
            print("pos %d (abs %d): NEVER WRITTEN" % (i, a))
            continue
        pc, t, n, v = wl[-1]
        tag = "OK" if v == blob[i] else "DIFF"
        print("pos %2d abs %d: n_writes=%d last pc=%x v=%08x %s"
              % (i, a, len(wl), pc, v, tag))
    n_emits = sum(1 for (pc, s, t, n, v) in ef if s == sva)
    print("\ntotal emits to source stream %x: %d" % (sva, n_emits))

json.dump({"finalq": finalq}, open(os.path.join(HERE, "_bdbg3_out.json"), "w"))
