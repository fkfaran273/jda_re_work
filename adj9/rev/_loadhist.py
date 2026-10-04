"""_loadhist.py - histogram of every load address (page) and every register
source of the sink EMITs, so we can see how descriptor words actually reach
the sink.  Also dumps the field-loop region of the program.
"""
import json, sys
from collections import Counter
sys.path.insert(0, ".")
import _taint as T
from fin_vm2 import FinEx
from vm_final import INS, IDX

i = int(sys.argv[1]) if len(sys.argv) > 1 else 0
steps = int(sys.argv[2]) if len(sys.argv) > 2 else 11_000_000
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

pg = Counter()
pcs = Counter()
orig = tn._apply
em = []


def apply(p):
    kind, extra, dests, srcs, snap = p
    for op in snap:
        if op[0] in ("load", "load2") and isinstance(op[1], int):
            pg[(op[1] >> 32) & 0xFFFFF] += 1
        if op[0] == "emit":
            em.append(op)
    pcs[kind] += 1
    return orig(p)


tn._apply = apply
ex.__dict__["_step_hook"] = tn.hook
st = ex.run(max_steps=steps)
print("status", st, "steps", ex.steps)
print("load pages (addr>>32 & 0xFFFFF): count")
for k, v in pg.most_common(20):
    print("   0x%05x00000000-ish  %d" % (k, v))
print("emit ops:", len(em), "first 6:", [(hex(a), hex(b), c, hex(dd)) for a, b, c, dd in em[:6]])
