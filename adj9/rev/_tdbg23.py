"""_tdbg23.py — probe the field loop (steps < 2200): what nodes do the
descriptor loads/EMITs get?  NEW file.
"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(400000)

import vm_taint as T
import vm_final as V

descs = T.corpus_row_descs(7)
second, cap = T.corpus_row(7)
ex = T.FinEx(second, descs)
tn = T.Taint(ex, T.default_seednames())
LOG = []
_orig_hook = tn.hook
STATE = {"n": 0}


def hook(exx=None):
    e = ex if exx is None else exx
    if STATE["n"] < 400:
        STATE["n"] += 1
        LOG.append((e.steps, e.pc, e.R.get("x27", 0), e.R.get("x8", 0),
                    e.R.get("w3", 0), str(tn.R.get("w3"))[:60],
                    str(tn.R.get("w8"))[:60]))
    return _orig_hook(e)


tn.hook = hook
ex.__dict__["_step_hook"] = hook
st = ex.run(max_steps=60_000_000)
if tn.pending is not None:
    tn._apply(tn.pending)
print("status=%s" % st, flush=True)
print("seeded:", tn.nseed, flush=True)
seen = set()
for s, pc, x27, x8, w3, w3n, w8n in LOG:
    k = V.IDX.get(pc)
    m, ops, _ = V.FAST[k] if k is not None else ("?", "?", 0)
    if m in ("ldr", "ldur", "rev", "str", "blr") or "w3" in ops[:4]:
        key = (pc, m)
        if key in seen and m not in ("rev",):
            continue
        seen.add(key)
        print("step=%d pc=%s (%s %s) x27=%x w3=%08x w3n=%s w8n=%s"
              % (s, hex(pc), m, ops, x27, w3, w3n, w8n), flush=True)
# check sink stream nodes for the first few field words
s0 = tn.s.get(0x5500000000)
if s0:
    for idx in sorted(s0.offs)[:8]:
        print("sink offs[%d] = %s" % (idx, str(s0.offs[idx])[:70]), flush=True)
