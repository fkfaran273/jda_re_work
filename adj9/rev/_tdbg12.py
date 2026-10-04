"""_tdbg12.py — automated backward chain: from the first S-dependent K-node
event, walk back through queue pushes / LENQ reads / slot writes to the origin
op.  NEW file.
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


# run 2: just values (emits only) to build the S-dependent value multiset
ex2, st2, PH2, EH2, _ = run(descs2, full=True)
V2 = {}
for e in EH2:
    V2[(e[1], e[2], e[3])] = e[4]
print("run2 emits %d" % len(EH2), flush=True)
del ex2, PH2, EH2

ex1, st1, PH1, EH1, LQ1 = run(descs, full=True)
print("run1 emits %d lenqs %d pushes %d" % (len(EH1), len(LQ1), len(PH1)),
      flush=True)
blob, stream = T.blob_from_ex(ex1, second)
print("blob_match=", blob == cap, flush=True)

# first S-dependent K-node event in run1 (emits + lenq reads), by step
evs = []
for e in EH1:
    if e[5][0] == "k" and V2.get((e[1], e[2], e[3])) not in (None, e[4]):
        evs.append(("EMIT",) + e)
for l in LQ1:
    if l[5][0] == "k" and V2.get((l[1], l[2], l[3])) not in (None, l[4]):
        evs.append(("LENQ",) + l)
evs.sort(key=lambda t: t[1])
print("S-dependent K-node events: %d; first at step %d (%s)"
      % (len(evs), evs[0][1], evs[0][0]), flush=True)

PH1s = sorted(PH1, key=lambda t: t[0])
LQ1s = sorted(LQ1, key=lambda t: t[0])
EH1s = sorted(EH1, key=lambda t: t[0])
push_steps = [t[0] for t in PH1s]
lq_steps = [t[0] for t in LQ1s]
em_steps = [t[0] for t in EH1s]


def last_before(arr, steps, t, pred):
    """last entry in arr with step < t and pred(entry)"""
    i = bisect.bisect_left(steps, t)
    for k in range(i - 1, -1, -1):
        if pred(arr[k]):
            return arr[k]
    return None


# walk back from the first event
kind0, s0, sv0, top0, n0, v0, nd0 = evs[0]
print("START %s step=%d s=%05x top=%s n=%d v=%08x nd=%s"
      % (kind0, s0, sv0, top0, n0, v0, str(nd0)[:50]), flush=True)
t = s0
v = v0
for hop in range(14):
    # the value v entered w0/w2/w3 from a LENQ or a PUSH just before t
    lq = last_before(LQ1s, lq_steps, t, lambda e: e[4] == v)
    pu = last_before(PH1s, push_steps, t, lambda e: e[1] == v)
    if lq is None and pu is None:
        print("hop %d: no source found for v=%08x before step %d (ALU origin?)"
              % (hop, v, t), flush=True)
        break
    # pick whichever is closer to t
    pick = None
    if lq and pu:
        pick = "LENQ" if lq[0] > pu[0] else "PUSH"
    else:
        pick = "LENQ" if lq else "PUSH"
    if pick == "LENQ":
        t2, sv2, top2, n2, v2, nd2 = lq
        print("hop %d <- LENQ step=%d s=%05x top=%s n=%d v=%08x nd=%s"
              % (hop, t2, sv2, top2, n2, v2, str(nd2)[:50]), flush=True)
        idx = (top2 + n2) & 0xFFFFFFFF
        w = last_before(EH1s, em_steps, t2,
                        lambda e: e[1] == sv2 and ((e[2] + e[3]) & 0xFFFFFFFF) == idx)
        if w is None:
            print("   no prior writer of slot %05x[%d]" % (sv2, idx), flush=True)
            break
        t3, sv3, top3, n3, v3, nd3 = w
        print("   writer: EMIT step=%d s=%05x top=%s n=%d v=%08x nd=%s"
              % (t3, sv3, top3, n3, v3, str(nd3)[:60]), flush=True)
        if nd3[0] != "k":
            print("   *** writer node is TAINTED — provenance was available! ***",
                  flush=True)
            break
        t, v = t3, v3
    else:
        t2, v2, nd2 = pu
        print("hop %d <- PUSH step=%d v=%08x nd=%s"
              % (hop, t2, v2, str(nd2)[:50]), flush=True)
        if nd2[0] != "k":
            print("   *** push node is TAINTED ***", flush=True)
            break
        t, v = t2, v2
