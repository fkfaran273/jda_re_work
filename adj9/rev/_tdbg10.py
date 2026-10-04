"""_tdbg10.py — scan the dual-run push/emit histories for the FIRST
S-dependent value carried by a K-constant node in both runs = the exact
provenance bug.  Never prints big node strings.
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
P = 4
lendl, tag, data = descs[P]
descs2 = list(descs)
descs2[P] = (lendl, tag, struct.pack(">I", d2w ^ 1) + data[4:])


def run(descs):
    T._INTERN.clear(); T._VCACHE.clear(); T._SEEDVAL.clear(); T._RNDVAL.clear()
    T.NNODE[0] = 0
    ex = T.TaintEx(second, descs, seednames=T.default_seednames())
    PH, EH = [], []

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
print("two runs %.0fs pushes %d/%d emits %d/%d"
      % (time.time() - t0, len(PH1), len(PH2), len(EH1), len(EH2)), flush=True)


def kind(nd):
    if nd[0] == "k":
        return "k"
    return "tainted"


n = min(len(PH1), len(PH2))
first_k = None
counts = {"kk": 0, "kt": 0, "tk": 0, "tt": 0}
for k in range(n):
    s1, v1, nd1 = PH1[k]
    s2, v2, nd2 = PH2[k]
    if v1 != v2:
        key = kind(nd1) + kind(nd2)
        counts[key] = counts.get(key, 0) + 1
        if key == "kk" and first_k is None:
            first_k = k
print("push value-diff classification:", counts, flush=True)
if first_k is not None:
    for k in range(first_k, min(first_k + 4, n)):
        s1, v1, nd1 = PH1[k]
        s2, v2, nd2 = PH2[k]
        print("first K-push idx=%d step=%d/%d v=%08x/%08x"
              % (k, s1, s2, v1, v2), flush=True)
        print("   nd1=%s" % (str(nd1)[:70],))
        print("   nd2=%s" % (str(nd2)[:70],))
m = min(len(EH1), len(EH2))
first_ke = None
countse = {}
for k in range(m):
    e1, e2 = EH1[k], EH2[k]
    if e1[4] != e2[4]:
        key = kind(e1[5]) + kind(e2[5])
        countse[key] = countse.get(key, 0) + 1
        if key == "kk" and first_ke is None:
            first_ke = k
print("emit value-diff classification:", countse, flush=True)
if first_ke is not None:
    for k in range(first_ke, min(first_ke + 4, m)):
        e1, e2 = EH1[k], EH2[k]
        print("first K-emit idx=%d step=%d s=%05x top=%s n=%d v=%08x/%08x"
              % (k, e1[0], e1[1], e1[2], e1[3], e1[4], e2[4]), flush=True)
        print("   nd1=%s" % (str(e1[5])[:70],))
        print("   nd2=%s" % (str(e2[5])[:70],))
