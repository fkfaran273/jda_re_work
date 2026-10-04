"""_tdbg16.py — dual-run diff on the NEW vm_taint: first index-aligned event
(push/lenq/emit) whose value differs across runs (S vs S^1) while both nodes
are K leaves.  NEW file.
"""
import os, sys, struct, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(300000)

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
    T.NNODE[0] = 0; T.UNK[0] = 0
    ex = T.TaintEx(second, descs, seednames=T.default_seednames())
    PH, EH, LQ = [], [], []
    _op = ex.queues  # unused
    # wrap queue storage: intercept the lists FinEx creates
    _oe = T.TaintStream.emit_t
    _ol = T.TaintStream.lenq_t

    def emit_t(self, n, v, node):
        r = _oe(self, n, v, node)
        EH.append((ex.steps, self.va & 0xFFFFF, self.top[-1],
                   n & T.M32, v & T.M32, node))
        return r

    def lenq_t(self, n):
        v, nd = _ol(self, n)
        LQ.append((ex.steps, self.va & 0xFFFFF, self.top[-1],
                   n & T.M32, v & T.M32, nd))
        return v, nd
    T.TaintStream.emit_t = emit_t
    T.TaintStream.lenq_t = lenq_t
    # queue pushes/pops: wrap the queues dict values
    real_q = ex.queues

    class QW(list):
        def insert(self, i, item):
            if isinstance(item, tuple) and len(item) == 2:
                PH.append((ex.steps, item[0], item[1]))
            return list.insert(self, i, item)
    for qva in list(real_q.keys()):
        pass
    # monkeypatch setdefault path by wrapping dict
    class QD(dict):
        def setdefault(self, qva, default=None):
            if qva not in self:
                self[qva] = QW()
            return self[qva]
    ex.queues = QD(real_q)
    st = ex.run(max_steps=20_000_000)
    T.TaintStream.emit_t = _oe
    T.TaintStream.lenq_t = _ol
    return ex, st, PH, EH, LQ


t0 = time.time()
ex1, st1, PH1, EH1, LQ1 = run(descs)
ex2, st2, PH2, EH2, LQ2 = run(descs2)
print("runs %.0fs status %s/%s pushes %d/%d emits %d/%d lenqs %d/%d unk=%d"
      % (time.time() - t0, st1, st2, len(PH1), len(PH2), len(EH1), len(EH2),
         len(LQ1), len(LQ2), T.UNK[0]), flush=True)
blob1, s1 = T.blob_from_ex(ex1, second)
blob2, s2 = T.blob_from_ex(ex2, second)
print("blob1==cap %s  blob2==cap %s" % (blob1 == cap, blob2 == cap), flush=True)

n = min(len(PH1), len(PH2))
cnt = {}
first_kp = None
for k in range(n):
    if PH1[k][1] != PH2[k][1]:
        key = (PH1[k][2][0] if not (PH1[k][2][0] == "k") else "k") + \
              (PH2[k][2][0] if not (PH2[k][2][0] == "k") else "k")
        cnt[key] = cnt.get(key, 0) + 1
        if key == "kk" and first_kp is None:
            first_kp = k
print("push diffs:", cnt, "first kk push idx:", first_kp, flush=True)
if first_kp is not None:
    for k in range(first_kp, first_kp + 3):
        print("  push#%d step=%d/%d v=%08x/%08x nd1=%s nd2=%s"
              % (k, PH1[k][0], PH2[k][0], PH1[k][1], PH2[k][1],
                 str(PH1[k][2])[:80], str(PH2[k][2])[:80]), flush=True)
m = min(len(EH1), len(EH2))
cnte = {}
first_ke = None
for k in range(m):
    if EH1[k][4] != EH2[k][4]:
        key = ("k" if EH1[k][5][0] == "k" else EH1[k][5][0]) + \
              ("k" if EH2[k][5][0] == "k" else EH2[k][5][0])
        cnte[key] = cnte.get(key, 0) + 1
        if key == "kk" and first_ke is None:
            first_ke = k
print("emit diffs:", cnte, "first kk emit idx:", first_ke, flush=True)
if first_ke is not None:
    for k in range(first_ke, first_ke + 3):
        e1, e2 = EH1[k], EH2[k]
        print("  emit#%d step=%d/%d s=%05x top=%s n=%d v=%08x/%08x "
              "nd1=%s nd2=%s" % (k, e1[0], e2[0], e1[1], e1[2], e1[3],
                                 e1[4], e2[4], str(e1[5])[:80],
                                 str(e2[5])[:80]), flush=True)
