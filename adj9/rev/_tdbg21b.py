"""_tdbg21.py — first divergent register write: record all w-register writes
with value < 0x200 in both runs (index-aligned), find the first divergence,
and show its node + the instruction.  NEW file.
"""
import os, sys, struct
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
    EV = []
    _osr = T.TaintEx.set_reg

    def set_reg(self, name, val, node):
        r = _osr(self, name, val, node)
        if name[0] == "w" and (val & T.M32) < 0x200:
            EV.append((self.steps, self.pc, name, val & T.M32, node))
        return r
    T.TaintEx.set_reg = set_reg
    st = ex.run(max_steps=20_000_000)
    T.TaintEx.set_reg = _osr
    return ex, st, EV


ex1, st1, EV1 = run(descs)
ex2, st2, EV2 = run(descs2)
print("events %d/%d" % (len(EV1), len(EV2)), flush=True)
n = min(len(EV1), len(EV2))
kd = [k for k in range(n) if EV1[k][3] != EV2[k][3]]
k0 = None
for k in kd:
    if EV1[k][4][0] == "k":
        k0 = k
        break
print("divergent writes: %d; first K-typed at idx %s" % (len(kd), k0), flush=True)
print("first 6 divergent (any node):", [(EV1[k][0], hex(EV1[k][1]), EV1[k][2],
      EV1[k][3], EV2[k][3], EV1[k][4][0]) for k in kd[:6]], flush=True)
if k0 is None:
    k0 = kd[0]
for k in range(k0, min(k0 + 6, n)):
    s, pc, name, val, node = EV1[k]
    s2, pc2, name2, val2, node2 = EV2[k]
    kk = V.IDX.get(pc)
    m, ops, _ = V.FAST[kk] if kk is not None else ("?", "?", 0)
    print("  idx=%d step=%d/%d pc=%s (%s %s) %s val=%08x/%08x\n      nd1=%s\n      nd2=%s"
          % (k, s, s2, hex(pc), m, ops, name, val, val2, str(node)[:130],
             str(node2)[:130]), flush=True)
# context: 12 events before
print("context before (run1):", flush=True)
for k in range(max(0, k0 - 12), k0):
    s, pc, name, val, node = EV1[k]
    kk = V.IDX.get(pc)
    m, ops, _ = V.FAST[kk] if kk is not None else ("?", "?", 0)
    print("  idx=%d step=%d pc=%s (%s %s) %s=%d nd0=%s"
          % (k, s, hex(pc), m, ops, name, val, node[0]), flush=True)
