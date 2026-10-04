"""_tdbg13.py — corrected onion walk: S-dependence tested by exact step
alignment between two runs; walk back from the first S-dependent K-node event
to the origin.  NEW file.
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
V2 = {}
for e in EH2:
    V2[("E", e[1], e[2], e[3], e[0])] = e[4]
for l in LQ2:
    V2[("L", l[1], l[2], l[3], l[0])] = l[4]
print("run2 done: emits %d lenqs %d pushes %d"
      % (len(EH2), len(LQ2), len(PH2)), flush=True)
del ex2, EH2, LQ2

ex1, st1, PH1, EH1, LQ1 = run(descs, full=True)
blob, stream = T.blob_from_ex(ex1, second)
print("run1 done blob_match=", blob == cap, flush=True)

evs = []
for e in EH1:
    if e[5][0] == "k" and V2.get(("E", e[1], e[2], e[3], e[0])) not in (None, e[4]):
        evs.append(("EMIT",) + e)
for l in LQ1:
    if l[5][0] == "k" and V2.get(("L", l[1], l[2], l[3], l[0])) not in (None, l[4]):
        evs.append(("LENQ",) + l)
evs.sort(key=lambda t: t[1])
print("S-dependent K-node events: %d; first at step %d (%s)"
      % (len(evs), evs[0][1], evs[0][0]), flush=True)

PH1s = sorted(PH1, key=lambda t: t[0])
push_steps = [t[0] for t in PH1s]
LQ1s = sorted(LQ1, key=lambda t: t[0])
lq_steps = [t[0] for t in LQ1s]
EH1s = sorted(EH1, key=lambda t: t[0])
em_steps = [t[0] for t in EH1s]
by_slot = {}
for e in EH1s:
    by_slot.setdefault((e[1], (e[2] + e[3]) & 0xFFFFFFFF), []).append(e)
slot_steps = {k: [x[0] for x in v] for k, v in by_slot.items()}


def last_before(arr, steps, t, pred):
    i = bisect.bisect_left(steps, t)
    for k in range(i - 1, -1, -1):
        if pred(arr[k]):
            return arr[k]
    return None


kind0, s0, sv0, top0, n0, v0, nd0 = evs[0]
print("START %s step=%d s=%05x top=%s n=%d v=%08x nd=%s"
      % (kind0, s0, sv0, top0, n0, v0, str(nd0)[:50]), flush=True)
t, v = s0, v0
origin = None
for hop in range(20):
    pu = last_before(PH1s, push_steps, t, lambda e: e[1] == v)
    lq = last_before(LQ1s, lq_steps, t, lambda e: e[4] == v)
    pick = None
    if pu and lq:
        pick = "PUSH" if pu[0] > lq[0] else "LENQ"
    elif pu:
        pick = "PUSH"
    elif lq:
        pick = "LENQ"
    if pick == "PUSH":
        t2, v2, nd2 = pu
        print("hop %d <- PUSH step=%d v=%08x nd=%s" % (hop, t2, v2, str(nd2)[:60]),
              flush=True)
        if nd2[0] != "k":
            print("*** PUSH node tainted — done ***", flush=True)
            break
        t, v = t2, v2
    elif pick == "LENQ":
        t2, sv2, top2, n2, v2, nd2 = lq
        print("hop %d <- LENQ step=%d s=%05x top=%s n=%d v=%08x nd=%s"
              % (hop, t2, sv2, top2, n2, v2, str(nd2)[:60]), flush=True)
        idx = (top2 + n2) & 0xFFFFFFFF
        w = last_before(by_slot.get((sv2, idx), []), slot_steps.get((sv2, idx), []),
                        t2, lambda e: True)
        if w is None:
            print("*** slot %05x[%d] had NO prior emit writer: LENQ nd-fallback "
                  "fabricated K(v) — the offs value was stocked WITHOUT a node "
                  "***" % (sv2, idx), flush=True)
            origin = ("no-writer", sv2, idx)
            break
        t3, sv3, top3, n3, v3, nd3 = w
        print("   writer: EMIT step=%d s=%05x top=%s n=%d v=%08x nd=%s"
              % (t3, sv3, top3, n3, v3, str(nd3)[:60]), flush=True)
        if nd3[0] != "k":
            print("*** writer node TAINTED but LENQ returned K — nd table lost "
                  "the entry ***", flush=True)
            origin = ("nd-lost", sv3, idx, t3)
            break
        t, v = t3, v3
    else:
        print("hop %d: ALU origin at step %d for v=%08x" % (hop, t, v),
              flush=True)
        origin = ("alu", t, v)
        break

if origin and origin[0] == "alu":
    print("tracing window around ALU origin step %d" % origin[1], flush=True)
    ex3 = T.TaintEx(second, descs, seednames=T.default_seednames())
    ex3.__dict__["_tracewin"] = (origin[1] - 120, origin[1] + 4)
    st3 = ex3.run(max_steps=20_000_000)
    LOGSN = []
    _osn = T.TaintEx.setnode

    def setnode(self, name, nd):
        r = _osn(self, name, nd)
        if origin[1] - 120 <= self.steps <= origin[1] + 4:
            LOGSN.append((self.steps, name, self.R.get(name, 0), nd))
        return r
    T.TaintEx.setnode = setnode
    ex3.__dict__["_tracewin"] = (origin[1] - 120, origin[1] + 4)
    ex3.run(max_steps=20_000_000)
    sn = {}
    for s, name, val, nd in LOGSN:
        sn.setdefault(s, []).append((name, val, nd))
    for s, pc, m, ops in ex3.__dict__["_twlog"]:
        print("  step=%d pc=%s %s %s" % (s, hex(pc), m, ops), flush=True)
        for name, val, nd in sn.get(s, []):
            print("      %-4s = %08x nd=%s" % (name, val & 0xFFFFFFFF,
                                               str(nd)[:110]), flush=True)
