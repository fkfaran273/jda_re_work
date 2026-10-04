"""lenq2_probe.py - deeper LENQ read: full memory-sourced list + per-stream roles.

lenq_probe found: seg27 is the ONLY signing-like segment; 11 distinct singles
total (9/11 inside seg27 itself); LENQ tops are queue indices (c9/89/69/59 =
201/137/105/89: VM queue positions, not data); memory-sourced (never emitted)
values = 45 distinct, only top shown. This probe:
 1. prints ALL 45 memory-sourced values with counts;
 2. per top LENQ stream: value histogram (are streams queues or tables?);
 3. xrefs memory-sourced values against seg27 roles (#2-cand, tile, #4);
 4. the (st,n)->v mapping: which (stream,slot) reads return the SAME value
    every time (= descriptor slots read from memory)?
"""
import json, os, struct, sys
from collections import Counter, defaultdict
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
L = d.get("lenq", [])
print("LENQ reads: %d" % len(L))
print("LENQ entry format:", L[0] if L else "EMPTY")


def be4(v):
    return "%08x" % (v & 0xFFFFFFFF)


emitted = set()
for st, n, v in d["emits"]:
    emitted.add(v & 0xFFFFFFFF)
lvals = Counter()
slotmap = defaultdict(Counter)   # (st,n) -> Counter(v)
for e in L:
    st, n, v = e[0], e[1], e[2]
    v &= 0xFFFFFFFF
    lvals[v] += 1
    slotmap[(st, n)][v] += 1
mem = sorted(((v, c) for v, c in lvals.items() if v not in emitted),
             key=lambda x: -x[1])
print("--- ALL memory-sourced values (%d) ---" % len(mem))
for v, c in mem:
    print("  %s x%d" % (be4(v), c))
print("--- stable slots: (stream,slot) -> single value, reads>=5 ---")
nstable = 0
for (st, n), c in sorted(slotmap.items(), key=lambda x: str(x[0])):
    if sum(c.values()) >= 5 and len(c) == 1:
        v = next(iter(c))
        print("  (%s,%s) = %s x%d" % (st, n, be4(v), sum(c.values())))
        nstable += 1
        if nstable > 60:
            print("  ... (truncated)")
            break
print("stable slots total (reads>=5, 1 value):",
      sum(1 for c in slotmap.values() if sum(c.values()) >= 5 and len(c) == 1))
# xref vs seg27 roles
seg27 = {"d2cand": 0xcd9d3a91, "a6hi": 0x00010201}
print("--- xref: seg27 role values in LENQ? ---")
for nm, v in seg27.items():
    print("  %s=%08x LENQ-reads=%d" % (nm, v, lvals.get(v, 0)))
print("--- top LENQ stream value histograms ---")
streams = Counter()
for e in L:
    streams[e[0]] += 1
for st, c in streams.most_common(4):
    vals = Counter()
    for e in L:
        if e[0] == st:
            vals[e[2] & 0xFFFFFFFF] += 1
    print("  stream %s reads=%d distinct=%d top=%s" %
          (st, c, len(vals), [("%08x" % v, k) for v, k in vals.most_common(6)]))
