"""_tdbg18.py — full queue-aware onion walk on the fixed vm_taint.

Records pushes/pops per qva, lenqs, emits for both runs (S, S^1).  Simulates
each queue (LIFO + CAP swap/push) so every pop maps to its producing push
instance.  Walks back from the first divergence to the origin instruction and
dumps the trace window there.  NEW file.
"""
import os, sys, struct, time
from collections import defaultdict
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(300000)

import vm_taint as T
import vm_final as V

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
asg = T.json.load(open(os.path.join(HERE, "all_signings.json")))
d2w = struct.unpack(">I", bytes.fromhex(asg[7]["d2"]))[0]
P = 4
lendl, tag, data = descs[P]
descs2 = list(descs)
descs2[P] = (lendl, tag, struct.pack(">I", d2w ^ 1) + data[4:])


def run(descs):
    T._INTERN.clear(); T._VCACHE.clear(); T._SEEDVAL.clear(); T._RNDVAL.clear()
    T.NNODE[0] = 0; T.UNK[0] = 0
    ex = T.TaintEx(second, descs, seednames=T.default_seednames())
    PU, PO, EH, LQ = [], [], [], []

    class Q(list):
        qva = 0

        def insert(self, i, item):
            if isinstance(item, tuple) and len(item) == 2 and i == 0:
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
    _oe = T.TaintStream.emit_t
    _ol = T.TaintStream.lenq_t

    def emit_t(self, n, v, node):
        r = _oe(self, n, v, node)
        EH.append((ex.steps, self.va & 0xFFFFF, self.top[-1], n & T.M32,
                   v & T.M32, node))
        return r

    def lenq_t(self, n):
        v, nd = _ol(self, n)
        LQ.append((ex.steps, self.va & 0xFFFFF, self.top[-1], n & T.M32,
                   v & T.M32, nd))
        return v, nd
    T.TaintStream.emit_t = emit_t
    T.TaintStream.lenq_t = lenq_t
    st = ex.run(max_steps=20_000_000)
    T.TaintStream.emit_t = _oe
    T.TaintStream.lenq_t = _ol
    return ex, st, PU, PO, EH, LQ


t0 = time.time()
ex1, st1, PU1, PO1, EH1, LQ1 = run(descs)
ex2, st2, PU2, PO2, EH2, LQ2 = run(descs2)
print("runs %.0fs %s/%s pu %d/%d po %d/%d em %d/%d"
      % (time.time() - t0, st1, st2, len(PU1), len(PU2), len(PO1), len(PO2),
         len(EH1), len(EH2)), flush=True)
blob1, _ = T.blob_from_ex(ex1, second)
print("blob1==cap", blob1 == cap, flush=True)

# push value diffs (index-aligned)
dp = [k for k in range(min(len(PU1), len(PU2)))
      if PU1[k][2] != PU2[k][2] and PU1[k][3][0] == "k" and PU2[k][3][0] == "k"]
print("push value diffs: %d, first at idx %d (step %d)"
      % (len(dp), dp[0], PU1[dp[0]][0]) if dp else "none", flush=True)

# --- simulate queues to map each pop to its producing push idx -------------
pushrec = {}   # flat index -> (step, qva, v, node)
for k, e in enumerate(PU1):
    pushrec[k] = e
stk = defaultdict(list)      # qva -> list of push flat indices (head=front)
pop_src = {}                 # pop flat index -> push flat index
ip = 0
events = sorted([(e[0], 0, k) for k, e in enumerate(PU1)] +
                [(e[0], 1, k) for k, e in enumerate(PO1)])
prev_step = None
for s, kind, k in events:
    if prev_step is not None and s < prev_step:
        raise AssertionError("event order")
    prev_step = s
    if kind == 0:
        stk[PU1[k][1]].insert(0, k)
    else:
        q = PO1[k][1]
        if stk[q]:
            pop_src[k] = stk[q].pop(0)
        else:
            pop_src[k] = None
print("simulated; pops mapped: %d" % len(pop_src), flush=True)

# index of the pop event nearest before a push (the value source)
PO1s = PO1  # already in order
def pop_before(t, v):
    for k in range(len(PO1s) - 1, -1, -1):
        if PO1s[k][0] < t:
            if PO1s[k][2] == v:
                return k
            if PO1s[k][0] < t - 40:
                return None
    return None


def lenq_before(t, v):
    for k in range(len(LQ1) - 1, -1, -1):
        if LQ1[k][0] < t:
            if LQ1[k][4] == v:
                return k
            if LQ1[k][0] < t - 40:
                return None
    return None


by_slot = {}
for e in sorted(EH1, key=lambda z: z[0]):
    by_slot.setdefault((e[1], (e[2] + e[3]) & T.M32), []).append(e)


def slot_writer(sva, idx, t):
    for e in reversed(by_slot.get((sva, idx), [])):
        if e[0] < t:
            return e
    return None


# walk: start from first differing push
k0 = dp[0]
chain = []
k = k0
for hop in range(60):
    step, qva, v, nd = PU1[k]
    # value source: the pop or lenq just before this push
    pk = pop_before(step, v)
    lk = lenq_before(step, v)
    if pk is None and lk is None:
        print("hop %d: push#%d step=%d q=%x v=%08x — ALU/literal origin"
              % (hop, k, step, qva, v), flush=True)
        chain.append(("ALU", step, v))
        break
    if pk is not None and (lk is None or PO1s[pk][0] > LQ1[lk][0]):
        src = PO1s[pk][0]
        srcpush = pop_src.get(pk)
        print("hop %d: push#%d(step %d v=%08x) <- pop#%d(step %d) <- push#%s"
              % (hop, k, step, v, pk, src, srcpush), flush=True)
        if srcpush is None:
            print("   pop from empty queue (underflow, v=0)", flush=True)
            break
        chain.append(("POP", src, PO1s[pk][2]))
        k = srcpush
    else:
        lq = LQ1[lk]
        print("hop %d: push#%d(step %d v=%08x) <- LENQ step=%d s=%05x top=%s "
              "n=%d v=%08x" % (hop, k, step, v, lq[0], lq[1], lq[2], lq[3],
                               lq[4]), flush=True)
        idx = (lq[2] + lq[3]) & T.M32
        w = slot_writer(lq[1], idx, lq[0])
        if w is None:
            print("   slot %05x[%d] never written by EMIT!" % (lq[1], idx),
                  flush=True)
            break
        print("   writer EMIT step=%d s=%05x top=%s n=%d v=%08x node0=%s"
              % (w[0], w[1], w[2], w[3], w[4], w[5][0]), flush=True)
        # find the push that produced this emit's w3: nearest push before w[0]
        # with value w[4]... use pop_before
        pw = pop_before(w[0], w[4])
        if pw is None:
            print("   emit source not found (ALU origin?)", flush=True)
            chain.append(("ALU", w[0], w[4]))
            break
        sp = pop_src.get(pw)
        print("   emit w3 <- pop step=%d <- push#%s" % (PO1s[pw][0], sp),
              flush=True)
        if sp is None:
            break
        chain.append(("EMIT", w[0], w[4]))
        k = sp

# trace the final origin
if chain:
    last = chain[-1]
    print("origin: %s at step %d value %08x" % last, flush=True)
    s0 = last[1]
    ex3 = T.TaintEx(second, descs, seednames=T.default_seednames())
    LOGSN = []
    _osn = T.TaintEx.set_reg

    def set_reg(self, name, val, node):
        r = _osn(self, name, val, node)
        if s0 - 80 <= self.steps <= s0 + 2:
            LOGSN.append((self.steps, self.pc, name, val, node))
        return r
    T.TaintEx.set_reg = set_reg
    ex3.__dict__["_tracewin"] = (s0 - 80, s0 + 2)
    ex3.run(max_steps=20_000_000)
    T.TaintEx.set_reg = _osn
    sn = {}
    for s, pc, name, val, node in LOGSN:
        sn.setdefault(s, []).append((pc, name, val, node))
    for s, pc, m, ops in ex3.__dict__.get("_twlog", []):
        print("  step=%d pc=%s %s %s" % (s, hex(pc), m, ops), flush=True)
        for pc2, name, val, node in sn.get(s, []):
            print("      %-4s = %08x nd=%s" % (name, val & T.M32,
                                               str(node)[:120]), flush=True)
