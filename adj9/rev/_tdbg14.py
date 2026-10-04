"""_tdbg14.py — onion walk v2: follow SLOT WRITERS only (emits), never
same-value pushes.  Start from the first step-aligned S-dependent K event.
NEW file.
"""
import os, sys, json, struct, time, bisect
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(200000)

import vm_taint as T

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
asg = T.json.load(open(os.path.join(HERE, "all_signings.json")))
d2w = struct.unpack(">I", bytes.fromhex(asg[7]["d2"]))[0]
P = 4
lendl, tag, data = descs[P]
descs2 = list(descs)
descs2[P] = (lendl, tag, struct.pack(">I", d2w ^ 1) + data[4:])


def run(descs, full=False):
    T._INTERN.clear(); T._VCACHE.clear(); T._SEEDVAL.clear(); T._RNDVAL.clear()
    T.NNODE[0] = 0
    ex = T.TaintEx(second, descs, seednames=T.default_seednames())
    PH, EH, LQ = [], [], []

    class Q(list):
        def insert(self, i, item):
            if isinstance(item, tuple) and len(item) == 2:
                PH.append((ex.steps, item[0], item[1]))
            return list.insert(self, i, item)

    class QD(dict):
        def setdefault(self, qva, default=None):
            if qva not in self:
                self[qva] = Q()
            return self[qva]
    ex.queues = QD(ex.queues)
    _oe = T.TaintStream.emit_t
    _ol = T.TaintStream.lenq_t

    def emit_t(self, n, v, node):
        r = _oe(self, n, v, node)
        if full:
            EH.append((ex.steps, self.va & 0xFFFFF, self.top[-1],
                       n & 0xFFFFFFFF, v & 0xFFFFFFFF, node))
        return r

    def lenq_t(self, n):
        v, nd = _ol(self, n)
        if full:
            LQ.append((ex.steps, self.va & 0xFFFFF, self.top[-1],
                       n & 0xFFFFFFFF, v & 0xFFFFFFFF, nd))
        return v, nd
    T.TaintStream.emit_t = emit_t
    T.TaintStream.lenq_t = lenq_t
    st = ex.run(max_steps=20_000_000)
    T.TaintStream.emit_t = _oe
    T.TaintStream.lenq_t = _ol
    return ex, st, PH, EH, LQ


ex2, st2, PH2, EH2, LQ2 = run(descs2, full=True)
V2E = {("E", e[1], e[2], e[3], e[0]): e[4] for e in EH2}
V2L = {("L", l[1], l[2], l[3], l[0]): l[4] for l in LQ2}
del ex2, EH2, LQ2
print("run2 done", flush=True)

ex1, st1, PH1, EH1, LQ1 = run(descs, full=True)
blob, stream = T.blob_from_ex(ex1, second)
print("run1 blob_match=", blob == cap, flush=True)

evs = []
for e in EH1:
    if e[5][0] == "k" and V2E.get(("E", e[1], e[2], e[3], e[0])) not in (None, e[4]):
        evs.append(("EMIT",) + e)
for l in LQ1:
    if l[5][0] == "k" and V2L.get(("L", l[1], l[2], l[3], l[0])) not in (None, l[4]):
        evs.append(("LENQ",) + l)
evs.sort(key=lambda t: t[1])
print("S-dependent K events: %d, first step %d (%s)"
      % (len(evs), evs[0][1], evs[0][0]), flush=True)

EH1s = sorted(EH1, key=lambda t: t[0])
by_slot = {}
for e in EH1s:
    by_slot.setdefault((e[1], (e[2] + e[3]) & 0xFFFFFFFF), []).append(e)
slot_steps = {k: [x[0] for x in v] for k, v in by_slot.items()}

kind0, s0, sv0, top0, n0, v0, nd0 = evs[0]
print("START %s step=%d s=%05x top=%s n=%d v=%08x nd=%s"
      % (kind0, s0, sv0, top0, n0, v0, str(nd0)[:60]), flush=True)
# if it's an EMIT, its w3 came from a queue; find the LENQ that fed it by
# scanning back for the nearest lenq with same value; else if LENQ start there.
t, v = s0, v0
seen = set()
for hop in range(30):
    if (t, v) in seen:
        print("loop detected at hop %d" % hop, flush=True)
        break
    seen.add((t, v))
    # find nearest lenq read of the same value before t
    cand = None
    for l in reversed(LQ1):
        if l[0] < t and l[4] == v:
            cand = l
            break
    if cand is None:
        print("hop %d: no LENQ source for v=%08x before step %d — origin is an "
              "ALU op or a literal that differs" % (hop, v, t), flush=True)
        break
    t2, sv2, top2, n2, v2, nd2 = cand
    print("hop %d <- LENQ step=%d s=%05x top=%s n=%d v=%08x nd=%s"
          % (hop, t2, sv2, top2, n2, v2, str(nd2)[:60]), flush=True)
    idx = (top2 + n2) & 0xFFFFFFFF
    arr = by_slot.get((sv2, idx), [])
    w = None
    for e in reversed(arr):
        if e[0] < t2:
            w = e
            break
    if w is None:
        print("*** slot %05x[%d] never written by an EMIT before this read: the "
              "value was stocked by something other than EMIT (PUSHS spill?) "
              "***" % (sv2, idx), flush=True)
        break
    t3, sv3, top3, n3, v3, nd3 = w
    print("   writer EMIT step=%d s=%05x top=%s n=%d v=%08x nd=%s"
          % (t3, sv3, top3, n3, v3, str(nd3)[:60]), flush=True)
    if nd3[0] != "k":
        print("*** writer node TAINTED — provenance existed at the writer! ***",
              flush=True)
        break
    t, v = t3, v3
