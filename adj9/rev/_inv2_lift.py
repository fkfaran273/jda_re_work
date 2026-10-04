"""_inv2_lift.py — lift the whitening phase site-by-site with ground truth."""
import gzip
import json
from collections import Counter

MAIN = 0x5450001000
REC_TOP, REC_N = 1134, 144

A = json.load(gzip.open("_inv2_row7_real.json.gz", "rt"))
wire = A["wire"]

# all MAIN-stream ops (E and Q) in order, with values
ops = []
for k, e in enumerate(wire):
    if e[2] == MAIN and e[0] in ("E", "Q"):
        ops.append((k, e[0], e[1], e[3] + e[4] if e[0] == "E" else e[4],
                    e[5] & 0xFFFFFFFF))
# find record build index
rb = next(k for k, (i, kind, pc, o, v) in enumerate(ops) if pc == 0x119538)
print("record build starts at wire idx", wire[rb][0] if False else ops[rb][0])

state = {}
# build state from ops BEFORE the whitening phase (from start to record build)
# simpler: track state through ALL ops; print phases from record build on.
phases = []
for (i, kind, pc, o, v) in ops[rb:]:
    phases.append((i, kind, pc, o, v))

# chronological phase list: group consecutive same-pc (ignoring Q noise)
groups = []
for (i, kind, pc, o, v) in phases:
    if groups and groups[-1][0] == pc:
        groups[-1][1].append((i, kind, o, v))
    else:
        groups.append([pc, [(i, kind, o, v)]])
print("total phase groups after record build:", len(groups))
for g in groups:
    pc, evs = g
    es = [(i, o, v) for (i, kind, o, v) in evs if kind == "E"]
    qs = [(i, o, v) for (i, kind, o, v) in evs if kind == "Q"]
    if len(es) >= 4 or len(qs) >= 4:
        lo = min(o for (_, o, _) in es) if es else min(o for (_, o, _) in qs)
        hi = max(o for (_, o, _) in es) if es else max(o for (_, o, _) in qs)
        print("  pc=%#x E=%4d Q=%4d abs=[%d..%d]" % (pc, len(es), len(qs), lo, hi))
