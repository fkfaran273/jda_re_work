"""harvest_an2.py - structural analysis of the live EMIT plane.
EMIT(q, n, v) => stream[q][base+n] = v   (vm_exec.py semantics).
Search for: (a) period-3 runs == the #0 tile [C1,C2,C3] repeating,
(b) period-4 runs == [W,C1,C2,C3], (c) constant streams (#8/#9 style),
(d) small-value/pointer-looking words.
"""
import base64
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)

d = json.load(open(os.path.join(HERE, "harvest_out.json"), encoding="utf-8"))
blob = base64.b64decode(d["blobB64"])
emits = d["emits"]
print("blob", len(blob), "B; emits", len(emits), "cap", d["nemits"])
if d.get("mapPairs"):
    print("map keys", len(d["mapPairs"]), "first", d["mapPairs"][0])

# group per stream, keep last write per n
S = {}
for q, n, v in emits:
    S.setdefault(q, {})[n] = v
print("streams:", len(S))

for q in sorted(S, key=lambda x: -len(S[x])):
    m = S[q]
    ns = sorted(m)
    vals = [m[n] for n in ns]
    print()
    print("stream q=%d  slots=%d  n=%d..%d  distinct=%d" %
          (q, len(m), ns[0], ns[-1], len(set(vals))))
    if len(vals) <= 64:
        print("   n->v:", [(n, "%08x" % m[n]) for n in ns])
        continue
    # period detection over consecutive runs
    for p in (3, 4, 8, 12, 16):
        best = None
        run = 0
        start = None
        for i in range(1, len(vals)):
            if vals[i] == vals[i - p]:
                if run == 0:
                    start = i - 1
                run += 1
            else:
                if best is None or run > best[0]:
                    best = (run, start)
                run = 0
        if best is None or run > best[0]:
            best = (run, start)
        if best and best[0] >= 6:
            r, st = best
            seg = vals[max(0, st - 2):st + p * 3 + 2]
            print("   period-%d run of %d at idx %d; triad/tile = %s" %
                  (p, r, st, ["%08x" % x for x in seg[:p * 2]]))
    print("   head:", ["%08x" % x for x in vals[:16]])
    print("   tail:", ["%08x" % x for x in vals[-16:]])