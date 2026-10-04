"""_bdbg5.py — unified backward dataflow walk over the wire log (v2).

For each blob word: walk (sva, abspos) backward.  A "copy" emit is detected
generically: an EMIT whose value equals a LENQ value logged within the
previous 40 wire events (copy loops LENQ then EMIT adjacently).  The walk
continues at the LENQ's (sva, top+n).  Terminal = no matching LENQ nearby
(compute site) or nothing wrote the position.
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
OUT = sys.argv[2] if len(sys.argv) > 2 else "_bdbg5_chains.json"

descs = corpus_row_descs(ROW)
second, cap = corpus_row(ROW)
ex = FinEx(second, descs)
ex.__dict__["_wire_log"] = []
t0 = time.time()
st = ex.run(max_steps=60_000_000)
WL = ex.__dict__["_wire_log"]
print("status=%s steps=%d nrand=%d %.0fs events=%d"
      % (st, ex.steps, ex.nrand, time.time() - t0, len(WL)), flush=True)

E_by_pos = defaultdict(list)      # (sva, abs) -> [seqno,...]
for si, ev in enumerate(WL):
    if ev[0] == "E":
        E_by_pos[(ev[2], ev[3] + ev[4])].append(si)


def last_E(sva, absidx, before):
    lst = E_by_pos.get((sva, absidx))
    if not lst:
        return None
    lo, hi = 0, len(lst)
    while lo < hi:
        mid = (lo + hi) // 2
        if lst[mid] < before:
            lo = mid + 1
        else:
            hi = mid
    return lst[lo - 1] if lo else None


def src_lenq(si, v):
    """Nearest Q event before si with value == v (within 40 events)."""
    for j in range(si - 1, max(-1, si - 41), -1):
        ev = WL[j]
        if ev[0] == "Q" and ev[5] == (v & 0xFFFFFFFF):
            return j
    return None


def walk(sva, absidx, before, depth=0):
    if depth > 120:
        return [("DEPTH", sva, absidx, before)]
    si = last_E(sva, absidx, before)
    if si is None:
        return [("UNWRITTEN", sva, absidx, before)]
    ev = WL[si]
    _, pc, esva, top, n, v = ev
    steps = [(si, "E", pc, esva, top + n, v)]
    qi = src_lenq(si, v)
    if qi is None:
        return steps                       # terminal compute site
    qev = WL[qi]
    _, qpc, qsva, qtop, qn, qv = qev
    qabs = qtop + qn
    if (qsva, qabs) == (esva, top + n):
        return steps                       # self-read (whitener output)
    return steps + walk(qsva, qabs, qi, depth + 1)


MAIN = 0x5450001000
fin_q = [i for i, ev in enumerate(WL) if ev[0] == "Q" and ev[1] == 0x117a00]
fq = WL[fin_q[0]]
base_abs = fq[3] + fq[4]
print("final base abs:", base_abs, "finq:", len(fin_q))

chains = {}
for i in range(48):
    chains[i] = walk(MAIN, base_abs + i, len(WL))

for i in range(48):
    ch = chains[i]
    print("\nw%-2d chainlen=%d" % (i, len(ch)))
    for s in ch:
        if s[0] in ("DEPTH", "UNWRITTEN"):
            print("   ", s)
        else:
            si, kind, pc, csva, absidx, v = s
            print("    si=%6d %s pc=%06x sva=%012x abs=%d v=%08x"
                  % (si, kind, pc, csva, absidx, v))

terms = Counter()
for i, ch in chains.items():
    last = ch[-1]
    terms[last[2] if last[0] not in ("DEPTH", "UNWRITTEN") else last[0]] += 1
print("\nterminal sites:", {hex(k) if isinstance(k, int) else k: v
                            for k, v in terms.items()})

json.dump({str(i): chains[i] for i in chains},
          open(os.path.join(HERE, OUT), "w"))
print("saved", OUT)
