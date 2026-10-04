"""_taintdecay.py - when does taint go to zero?  Reports the step of the last
nonzero taint, the peak popcount and its step, and the first 30 sink emits with
their taint, so we can see exactly which pass produces the final body.
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

st = {"last_nz": 0, "peak": 0, "peak_step": 0, "nz": 0}
sink0 = []
orig = tn._apply


def apply(p):
    for op in p[4]:
        if op[0] == "emit" and op[1] == T.SINK and op[2] == 0:
            sink0.append((ex.steps, op[3]))
    r = orig(p)
    m = 0
    for v in tn.R.values():
        m |= v
    if m:
        st["nz"] += 1
        st["last_nz"] = ex.steps
        b = bin(m).count("1")
        if b > st["peak"]:
            st["peak"] = b
            st["peak_step"] = ex.steps
    return r


tn._apply = apply
ex.__dict__["_step_hook"] = tn.hook
r = ex.run(max_steps=60_000_000)
print("status", r, "steps", ex.steps, st)
print("sink idx0 emits (step, popcount, leaves):")
for s, m in sink0:
    print("  %9d %2d  %s" % (s, bin(m).count("1"),
                             " ".join(names[b] for b in range(tn.nbits) if (m >> b) & 1)))
