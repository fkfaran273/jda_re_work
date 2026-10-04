"""_tdbg8.py — queue-history diff: first PUSH (or EMIT) whose value depends on
S.  Two runs with S and S^1, interning reset between runs; log every queue PUSH
with (step, qva, v, node).  Report the first few pushes where v differs and the
nodes in both runs.
NEW file.
"""
import os, sys, json, struct, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(200000)

import vm_taint as T

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
asg = T.json.load(open(os.path.join(HERE, "all_signings.json")))
d2w = struct.unpack(">I", bytes.fromhex(asg[7]["d2"]))[0]

P = 4  # VA order index of logical d2
lendl, tag, data = descs[P]
data2 = struct.pack(">I", d2w ^ 1) + data[4:]
descs2 = list(descs)
descs2[P] = (lendl, tag, data2)


def run(descs):
    T._INTERN.clear()
    T._VCACHE.clear()
    T._SEEDVAL.clear()
    T._RNDVAL.clear()
    T.NNODE[0] = 0
    ex = T.TaintEx(second, descs, seednames=T.default_seednames())
    PH = []
    orig = T.TaintEx.run.__wrapped__ if hasattr(T.TaintEx.run, "__wrapped__") else None
    # instrument OP_PUSH by wrapping queues: use a dict subclass? simpler:
    # monkeypatch T.TaintEx.run is too big; instead wrap the queues dict.
    class Q(list):
        def insert(self, i, item):
            if isinstance(item, tuple) and len(item) == 2:
                PH.append((ex.steps, id_q[0], item[0], item[1]))
            return list.insert(self, i, item)
    id_q = [0]
    orig_init = T.TaintEx.__init__

    def __init__(self, *a, **k):
        orig_init(self, *a, **k)
    # simpler: wrap setdefault via a proxy on self.queues
    class QD(dict):
        def setdefault(self, qva, default=None):
            if qva not in self:
                self[qva] = Q()
            return self[qva]
        def __getitem__(self, qva):
            v = dict.__getitem__(self, qva)
            return v
        def get(self, qva, default=None):
            return dict.get(self, qva, default)
    # rebind queues
    old_q = ex.queues
    ex.queues = QD(old_q)
    # stream emits too
    EH = []
    _oe = T.TaintStream.emit_t

    def emit_t(self, n, v, node):
        r = _oe(self, n, v, node)
        EH.append((ex.steps, self.va & 0xFFFFF, self.top[-1], n & 0xFFFFFFFF,
                   v & 0xFFFFFFFF, node))
        return r
    T.TaintStream.emit_t = emit_t
    st = ex.run(max_steps=20_000_000)
    T.TaintStream.emit_t = _oe
    return ex, st, PH, EH


t0 = time.time()
ex1, st1, PH1, EH1 = run(descs)
ex2, st2, PH2, EH2 = run(descs2)
print("two runs %.0fs status %s/%s pushes %d/%d emits %d/%d"
      % (time.time() - t0, st1, st2, len(PH1), len(PH2), len(EH1), len(EH2)),
      flush=True)

n = min(len(PH1), len(PH2))
shown = 0
for k in range(n):
    s1, q1, v1, nd1 = PH1[k]
    s2, q2, v2, nd2 = PH2[k]
    if v1 != v2:
        print("PUSH #%d step=%d/%d q=%x v=%08x/%08x" % (k, s1, s2, q1, v1, v2))
        print("   node1=%s" % (str(nd1)[:200],))
        print("   node2=%s" % (str(nd2)[:200],))
        shown += 1
        if shown >= 40:
            break
if shown == 0:
    print("no push differs?!")
# first EMIT value diff
m = min(len(EH1), len(EH2))
for k in range(m):
    e1, e2 = EH1[k], EH2[k]
    if e1[4] != e2[4]:
        print("first EMIT value diff #%d step=%d s=%05x top=%s n=%d "
              "v=%08x/%08x" % (k, e1[0], e1[1], e1[2], e1[3], e1[4], e2[4]))
        print("   node1=%s" % (str(e1[5])[:200],))
        print("   node2=%s" % (str(e2[5])[:200],))
        break
blob1, s1_ = T.blob_from_ex(ex1, second)
print("blob1==cap:", blob1 == cap, flush=True)
