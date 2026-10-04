"""_tdbg15.py — full queue simulation: record pushes and pops per queue with
(qva, v, node); map the pop that fed the origin emit back to its push; then
dump the instruction trace at that push to find the producing ALU op.
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

TARGET_STEP = 2851809   # writer EMIT of the K-node slot value
TARGET_V = 0xCB


def run(descs):
    T._INTERN.clear(); T._VCACHE.clear(); T._SEEDVAL.clear(); T._RNDVAL.clear()
    T.NNODE[0] = 0
    ex = T.TaintEx(second, descs, seednames=T.default_seednames())
    PU, PO = [], []

    class Q(list):
        qva = 0

        def insert(self, i, item):
            if isinstance(item, tuple) and len(item) == 2:
                PU.append((ex.steps, self.qva, item[0], item[1]))
            return list.insert(self, i, item)

        def pop(self, i=0):
            v = list.pop(self, i)
            if isinstance(v, tuple) and len(v) == 2:
                PO.append((ex.steps, self.qva, v[0], v[1]))
            return v

    class QD(dict):
        def setdefault(self, qva, default=None):
            if qva not in self:
                q = Q()
                q.qva = qva
                self[qva] = q
            return self[qva]
    ex.queues = QD(ex.queues)
    st = ex.run(max_steps=20_000_000)
    return ex, st, PU, PO


ex1, st1, PU1, PO1 = run(descs)
ex2, st2, PU2, PO2 = run(descs2)
print("runs done; pushes %d/%d pops %d/%d" % (len(PU1), len(PU2), len(PO1),
                                              len(PO2)), flush=True)

# map: pop at step t on queue q got the value pushed by which push?
# simulate: iterate pushes/pops in order; pops and pushes interleave per queue.
from collections import defaultdict
pu_by_step = defaultdict(list)
for k, (s, q, v, nd) in enumerate(PU1):
    pu_by_step[(q, s)].append(k)
po_src = []           # per pop record: index of producing push
open_q = defaultdict(list)   # qva -> list of push indices pending
pi = 0
events = sorted([(s, 0, k) for k, (s, q, v, nd) in enumerate(PU1)] +
                [(s, 1, k) for k, (s, q, v, nd) in enumerate(PO1)])
for s, kind, k in events:
    if kind == 0:
        q = PU1[k][1]
        open_q[q].append(k)
    else:
        q = PO1[k][1]
        src = open_q[q].pop(0) if open_q[q] else None
        po_src.append((PO1[k][0], q, PO1[k][2], src))
print("simulated %d pops (src=None means underflow)" % len(po_src), flush=True)

# find the pop nearest before TARGET_STEP with value TARGET_V
cands = [(s, q, v, src) for (s, q, v, src) in po_src if s < TARGET_STEP]
cands.sort()
pop = None
for s, q, v, src in reversed(cands):
    if s > TARGET_STEP - 400:
        pop = (s, q, v, src)
        break
print("origin pop: step=%d q=%x v=%08x src_push=%s"
      % (pop[0], pop[1], pop[2], pop[3]), flush=True)
k = pop[3]
while k is not None:
    s, q, v, nd = PU1[k]
    print("push #%d step=%d q=%x v=%08x nd0=%s" % (k, s, q, v, nd[0]), flush=True)
    if nd[0] != "k":
        print("*** tainted node reached ***", flush=True)
        break
    # find the pop this push fed (next pop on q after s)
    nxt = None
    for (s2, q2, v2, src2) in po_src:
        if src2 == k:
            nxt = (s2, q2, v2)
            break
    if nxt is None:
        break
    # continue from the push that fed that pop: find pop record index
    break
# the pop that consumed push k:
k = pop[3]
s_pop = None
for (s2, q2, v2, src2) in po_src:
    if src2 == k:
        s_pop = s2
        break
print("push consumed by pop at step %s" % s_pop, flush=True)

# trace the window before the push to see the producing op
s_push = PU1[k][0]
ex3 = T.TaintEx(second, descs, seednames=T.default_seednames())
LOGSN = []
_osn = T.TaintEx.setnode


def setnode(self, name, nd):
    r = _osn(self, name, nd)
    if s_push - 60 <= self.steps <= s_push + 2:
        LOGSN.append((self.steps, name, self.R.get(name, 0), nd))
    return r


T.TaintEx.setnode = setnode
ex3.__dict__["_tracewin"] = (s_push - 60, s_push + 2)
ex3.run(max_steps=20_000_000)
T.TaintEx.setnode = _osn
sn = {}
for s, name, val, nd in LOGSN:
    sn.setdefault(s, []).append((name, val, nd))
for s, pc, m, ops in ex3.__dict__["_twlog"]:
    print("  step=%d pc=%s %s %s" % (s, hex(pc), m, ops), flush=True)
    for name, val, nd in sn.get(s, []):
        print("      %-4s = %08x nd=%s" % (name, val & 0xFFFFFFFF,
                                           str(nd)[:130]), flush=True)
