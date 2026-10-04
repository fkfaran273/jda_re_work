"""_traceback.py - dump the last N instructions before the final sink emit of
body word 47, with the parse result and the live taint, to find the exact
instruction that drops the descriptor taint on the floor.
"""
import json, sys
from collections import deque
sys.path.insert(0, ".")
import _taint as T
from fin_vm2 import FinEx
from vm_final import INS, IDX

i = int(sys.argv[1]) if len(sys.argv) > 1 else 0
N = int(sys.argv[2]) if len(sys.argv) > 2 else 120
TARGET = int(sys.argv[3]) if len(sys.argv) > 3 else 47
rows = json.load(open("all_signings.json"))
ph3 = json.load(open("pair_h3.json"))
d = T.descs_of(rows[i])
ex = FinEx(ph3[i]["second"], d)
nd = []
for lendl, tag, data in d:
    raw = bytes(data)
    padded = raw + b"\x00" * (-len(raw) % 4)
    nd.append((max(int(lendl), len(padded) // 4), tag, padded))
tn = T.Taint(ex, nd)
T.LEAFBIT.update(tn.leaf)
names = ["d%d[%d]" % (T.VA_ORDER[di], j) for (di, j), _ in
         sorted(tn.leaf.items(), key=lambda kv: kv[1])]


def lbl(m):
    if not m:
        return "-"
    return ",".join(names[b] for b in range(tn.nbits) if (m >> b) & 1)


ring = deque(maxlen=N)
hit = []
orig = tn._apply


def apply(p):
    for op in p[4]:
        if op[0] == "emit" and op[1] == T.SINK and (op[2] & 0xFFFFFFFF) == TARGET:
            hit.append((ex.steps, list(ring), op[3]))
    r = orig(p)
    ins = INS[IDX[ex.pc]]
    kind, extra, dests, srcs, _ = T.parse(ex.pc)
    ring.append((ex.steps, ex.pc, ins.mnemonic, ins.op_str, kind,
                 list(dests), [lbl(tn.treg(s)) for s in srcs], p[4]))
    return r


tn._apply = apply
ex.__dict__["_step_hook"] = tn.hook
r = ex.run(max_steps=60_000_000)
print("status", r, "steps", ex.steps, "hits for idx%d: %d" % (TARGET, len(hit)))
if not hit:
    sys.exit()
st, ring, m = hit[-1]
print("=== final emit of idx%d at step %d, value taint=%s ===" % (TARGET, st, lbl(m)))
def sh(x):
    if isinstance(x, int):
        return lbl(x) if x and bin(x).count("1") > 1 else (hex(x) if x else "0")
    return str(x)


for rec in ring:
    s, pc, mn, ops, kind, dests, srct, snap = rec
    print("%9d %08x %-7s %-26s %-6s d=%s src=%s snap=%s" % (
        s, pc, mn, ops, kind, dests, srct,
        [o[0] + "(" + ",".join(sh(x) for x in o[1:]) + ")" for o in snap]))
