"""tile_fit.py - per-signing minimal tile of #0: golden pattern is
[W0][C1][C2][C3][W1][C1][C2][C3]x8 (5 distinct) but als9/det2 show 6 distinct.
Find for EACH of the 13 samples: the smallest (prefix, period) with
w[i] == w[prefix + (i-prefix)%period], and report prefix/period/distinct.
This tells us exactly which positions are variable (inputs) vs repeated fill.
"""
import os
import json
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
D = json.load(open(os.path.join(HERE, "det_full.json"), encoding="utf-8"))

rows = []
for s in A:
    rows.append(("als-" + s["d2"], struct.unpack(">36I", bytes.fromhex(s["d0"]))))
for s in D:
    d2 = "%08x" % s["d2"] if isinstance(s["d2"], int) else s["d2"]
    rows.append(("det-" + d2, struct.unpack(">36I", bytes.fromhex(s["d0"]))))

for tag, w in rows:
    best = None
    for pre in range(0, 9):
        for per in (1, 2, 3, 4, 5, 6, 7, 8):
            ok = all(w[i] == w[pre + (i - pre) % per] for i in range(pre, 36))
            if ok:
                best = (pre, per)
                break
        if best:
            break
    u = sorted(set(w))
    print("%-12s distinct=%d tile(prefix=%s,period=%s) w0-7=%s"
          % (tag, len(u), best[0] if best else "?", best[1] if best else "?",
             " ".join("%08x" % x for x in w[:8])))
print("done")
