"""_bdbg2.py — map the sink-stream EMIT sequence of a fast FinEx run."""
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
SINK = 0x5500000000

descs = corpus_row_descs(ROW)
second, cap = corpus_row(ROW)
ex = FinEx(second, descs)
ex.__dict__["_emit_pc"] = []          # (pc, sva, n, v) per EMIT
t0 = time.time()
st = ex.run(max_steps=60_000_000)
print("status=%s steps=%d nrand=%d %.0fs" % (st, ex.steps, ex.nrand,
                                             time.time() - t0), flush=True)

ep = ex.__dict__["_emit_pc"]
print("total emits:", len(ep))
per_stream = Counter(sva for (_, sva, _, _) in ep)
print("per-stream:", {hex(k): v for k, v in per_stream.items()})

last = {}
for (sva, n, v) in ex.emit_trace:
    last[(sva, n)] = v & 0xFFFFFFFF
words = [last.get((SINK, k), 0) for k in range(48)]
print("blob match:", b"".join(struct.pack(">I", w) for w in words) == cap)

# sink emit sequence: (emit_idx_global, pc, n, v)
seq = [(gi, pc, n, v) for gi, (pc, sva, n, v) in enumerate(ep) if sva == SINK]
print("SINK emits:", len(seq))
pc_hist = Counter(pc for (_, pc, _, _) in seq)
print("SINK emit PCs:", {hex(k): v for k, v in pc_hist.items()})

final_emit_idx = {}
seen = set()
for j in range(len(seq) - 1, -1, -1):
    n = seq[j][2]
    if n not in seen:
        seen.add(n)
        final_emit_idx[n] = j
print("final-emit idx/pc per word:")
for k in range(48):
    j = final_emit_idx.get(k)
    if j is None:
        print("w%-2d NEVER EMITTED" % k)
        continue
    gi, pc, n, v = seq[j]
    tag = "OK" if v == words[k] else "MISMATCH"
    print("w%-2d emit#%d(step? gi=%d) pc=%s v=%08x %s" % (k, j, gi, hex(pc), v, tag))

lastfin = max(final_emit_idx.values())
print("final emit at sink-emit#%d of %d; overwrites after: %d"
      % (lastfin, len(seq), len(seq) - 1 - lastfin))

print("\nemit window around each final emit:")
for k in range(48):
    j = final_emit_idx.get(k)
    if j is None:
        continue
    lo, hi = max(0, j - 2), min(len(seq), j + 2)
    ctx = ["%d:%s:%d:%08x" % (n_, hex(p_), n_, v_)
           for (gi, p_, n_, v_) in seq[lo:hi]]
    print("w%-2d ... %s ..." % (k, " | ".join(ctx)))
