"""_sinktrace.py - record EVERY sink EMIT (index, taint popcount, leaves) so we
can see whether body words are emitted once or re-emitted with clobbered taint.
"""
import json, sys
sys.path.insert(0, ".")
import _taint as T
from fin_vm2 import FinEx

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
T.LEAFBIT.update(tn.leaf)
names = ["d%d[%d]" % (T.VA_ORDER[di], j) for (di, j), _ in
         sorted(tn.leaf.items(), key=lambda kv: kv[1])]

log = []
orig = tn._apply


def apply(p):
    for op in p[4]:
        if op[0] == "emit" and op[1] == T.SINK:
            log.append((ex.steps, op[2] & M32 if False else op[2], op[3]))
    return orig(p)


M32 = 0xFFFFFFFF
tn._apply = apply
ex.__dict__["_step_hook"] = tn.hook
st = ex.run(max_steps=steps)
print("status", st, "steps", ex.steps, "sink emits:", len(log))
first = {}
for k, (s, n, m) in enumerate(log):
    first.setdefault(n, (k, s, m))
print("distinct indices:", len(first), "max index", max(first))
print("first 12 sink emits (step, idx, leaves):")
for s, n, m in log[:12]:
    print("  %9d idx=%-4d %s" % (s, n, " ".join(names[b] for b in range(tn.nbits) if (m >> b) & 1)))
print("...  last 12 sink emits:")
for s, n, m in log[-12:]:
    print("  %9d idx=%-4d %s" % (s, n, " ".join(names[b] for b in range(tn.nbits) if (m >> b) & 1)))
print("per-index: #emits, last taint leaves")
from collections import Counter
cnt = Counter(n for _, n, _ in log)
for n in sorted(first):
    lasts = [m for _, nn, m in log if nn == n][-1]
    print("  idx %-4d emits=%-6d %s" % (n, cnt[n],
          " ".join(names[b] for b in range(tn.nbits) if (lasts >> b) & 1)))
