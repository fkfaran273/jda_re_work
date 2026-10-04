"""_tdbg24.py — targeted: does the field-loop load at 0x10017c hit the seed
node in tn.mem?  NEW file.
"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(400000)

import vm_taint as T

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.FinEx(second, descs)
tn = T.Taint(ex, T.default_seednames())
print("seeded:", tn.nseed, flush=True)
hits = {}
for a in sorted(tn.mem)[:6]:
    print("tn.mem[%x] = %s" % (a, str(tn.mem[a])[:40]), flush=True)
print("ex.mem[0x5700000000] = %08x" % ex.mem.get(0x5700000000, 0), flush=True)

_orig_mem = tn._mem_apply
CNT = [0]


def mem_apply(m, o, pc):
    if pc == 0x10017c and CNT[0] < 4:
        CNT[0] += 1
        before = tn.R.get("w8")
        _orig_mem(m, o, pc)
        after = tn.R.get("w8")
        print("load@0x10017c #%d: w8 %s -> %s  (x8=%x x22=%x)"
              % (CNT[0], str(before)[:40], str(after)[:40],
                 ex.R.get("x8", 0), ex.R.get("x22", 0)), flush=True)
        return
    return _orig_mem(m, o, pc)


tn._mem_apply = mem_apply
ex.__dict__["_step_hook"] = tn.hook
st = ex.run(max_steps=60_000_000)
print("status=%s" % st, flush=True)
