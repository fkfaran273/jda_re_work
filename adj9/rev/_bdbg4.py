"""_bdbg4.py — backward dataflow walk from each of the 44 body words through
the VM's section-copy pipeline to the compute (whitener) emit sites.

Events (in global order):
  EMIT (pc, sva, top, n, v)      writes offs[sva][top+n] = v
  LENQ (pc, sva, n, top, v)      reads  offs[sva][top+n] -> v
  PUSH/POP (pc, qva, v)

Walk: target word = (MAIN, abs).  Find last EMIT writing it.  If that pc is a
copy emit, find the LENQ of the same (sva, abs, v) nearest before it, and
recurse on the last EMIT that wrote that position before the LENQ.  Terminal
= emit pc that is not a known copy site (or a POP value).
"""
import json
import os
import struct
import sys
import time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fin_vm2 import FinEx
from vm_taint import corpus_row_descs, corpus_row

ROW = int(sys.argv[1]) if len(sys.argv) > 1 else 7
MAIN = 0x5450001000

descs = corpus_row_descs(ROW)
second, cap = corpus_row(ROW)
ex = FinEx(second, descs)
ex.__dict__["_emit_full"] = []
ex.__dict__["_lenq_log"] = []
ex.__dict__["_qop_log"] = []
t0 = time.time()
st = ex.run(max_steps=60_000_000)
print("status=%s steps=%d nrand=%d %.0fs" % (st, ex.steps, ex.nrand,
                                             time.time() - t0), flush=True)

EF = ex.__dict__["_emit_full"]
LQ = ex.__dict__["_lenq_log"]
QO = ex.__dict__["_qop_log"]
print("emits=%d lenqs=%d qops=%d" % (len(EF), len(LQ), len(QO)))

# index events
# writers[(sva, abs)] = list of (order_idx, pc, v) in order
writers = defaultdict(list)
for oi, (pc, sva, top, n, v) in enumerate(EF):
    writers[(sva, top + n)].append((oi, pc, v))
# lenqs[(sva, abs)] = list of (order_idx, pc, v)
lenqs = defaultdict(list)
for oi, (pc, sva, n, top, v) in enumerate(LQ):
    lenqs[(sva, top + n)].append((oi, pc, v))

# the final blob words = LENQ at pc 0x117a00 of (MAIN, 337..384)
finalq = [e for e in LQ if e[0] == 0x117a00]
base_abs = finalq[0][3] + finalq[0][2]
print("final copy: MAIN abs %d..%d" % (base_abs, base_abs + 47))

# classify emit pcs by frequency (copy sites vs compute sites)
pc_hist = Counter(pc for (pc, sva, top, n, v) in EF)


def last_writer(sva, absidx, before_oi):
    wl = writers.get((sva, absidx))
    if not wl:
        return None
    lo, hi = 0, len(wl)
    while lo < hi:
        mid = (lo + hi) // 2
        if wl[mid][0] < before_oi:
            lo = mid + 1
        else:
            hi = mid
    return wl[lo - 1] if lo else None


def last_lenq(sva, absidx, before_oi, val=None):
    ll = lenqs.get((sva, absidx))
    if not ll:
        return None
    lo, hi = 0, len(ll)
    while lo < hi:
        mid = (lo + hi) // 2
        if ll[mid][0] < before_oi:
            lo = mid + 1
        else:
            hi = mid
    while lo:
        oi, pc, v = ll[lo - 1]
        if val is None or v == (val & 0xFFFFFFFF):
            return ll[lo - 1]
        lo -= 1
    return None


def walk(sva, absidx, before_oi, depth=0, seen=None):
    """Return a provenance chain list for the value at (sva, absidx)."""
    if seen is None:
        seen = set()
    key = (sva, absidx, before_oi)
    if key in seen or depth > 60:
        return [("LOOP", sva, absidx, before_oi)]
    seen = seen | {key}
    w = last_writer(sva, absidx, before_oi)
    if w is None:
        return [("UNWRITTEN", sva, absidx, before_oi)]
    oi, pc, v = w
    return [(oi, pc, sva, absidx, v)] + walk(sva, absidx, oi, depth + 1, seen)


chains = {}
for i in range(48):
    abs_i = base_abs + i
    # start: the last LENQ of (MAIN, abs_i) at pc 0x117a00
    lq = last_lenq(MAIN, abs_i, len(EF) + 1)
    # walk back: the writer of (MAIN, abs_i) before that lenq
    ch = walk(MAIN, abs_i, lq[0] if lq else len(EF) + 1)
    chains[i] = ch

for i in range(48):
    ch = chains[i]
    print("\nw%-2d len=%d" % (i, len(ch)))
    for step in ch[:12]:
        if step[0] in ("UNWRITTEN", "LOOP"):
            print("   ", step)
        else:
            oi, pc, sva, absidx, v = step
            print("    oi=%6d pc=%06x sva=%x abs=%d v=%08x"
                  % (oi, pc, sva, absidx, v))
    if len(ch) > 12:
        print("    ... (%d more)" % (len(ch) - 12))

# summary: terminal emit pc per body word
terms = Counter()
for i, ch in chains.items():
    last = ch[-1]
    terms[last[1] if last[0] not in ("UNWRITTEN", "LOOP") else last[0]] += 1
print("\nterminal sites:", {hex(k) if isinstance(k, int) else k: v
                            for k, v in terms.items()})

json.dump({str(i): [list(s) for s in chains[i]] for i in chains},
          open(os.path.join(HERE, "_bdbg4_chains.json"), "w"))
print("saved _bdbg4_chains.json")
