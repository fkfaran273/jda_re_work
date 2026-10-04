"""_finalreg.py - at the LAST sink emit of each body word, dump the taint of
every register and of the sink stream itself, so we can see where the chain to
the final value is being dropped.
"""
import json, sys
sys.path.insert(0, ".")
import _taint as T
from fin_vm2 import FinEx

i = int(sys.argv[1]) if len(sys.argv) > 1 else 0
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
    return " ".join(names[b] for b in range(tn.nbits) if (m >> b) & 1)


orig = tn._apply
last = {}


def apply(p):
    for op in p[4]:
        if op[0] == "emit" and op[1] == T.SINK:
            last[op[2] & 0xFFFFFFFF] = (ex.steps, op[3], dict(tn.R), ex.pc)
    return orig(p)


tn._apply = apply
ex.__dict__["_step_hook"] = tn.hook
r = ex.run(max_steps=60_000_000)
print("status", r, "steps", ex.steps)
for n in range(0, 8):
    s, m, regs, pc = last[n]
    nz = {c: lbl(v) for c, v in regs.items() if v}
    print("idx %d step=%d emitmask=%d  nzregs=%s" % (n, s, bin(m).count("1"), nz))
print("...")
for n in range(44, 48):
    s, m, regs, pc = last[n]
    nz = {c: lbl(v) for c, v in regs.items() if v}
    print("idx %d step=%d emitmask=%d  nzregs=%s" % (n, s, bin(m).count("1"), nz))
