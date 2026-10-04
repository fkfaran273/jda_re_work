"""diff_body.py — placeholder-vs-live per-dword diff to localize #0's influence."""
import sys
sys.path.insert(0, ".")
import struct
import recompute_body as R

rounds = R.live_field_values()
descs = R.build_descriptors(rounds[0] if rounds else [])
ex, status = R.run(descs, R.SESSION_SECOND)
print("status:", status, "steps:", ex.steps)
from collections import defaultdict
sinks = defaultdict(dict)
for (s, n, v) in ex.emit_trace:
    sinks[s][n] = v
t = __import__("json").load(open("target_body.json"))
live = [int(x, 16) for x in t["body_dwords_hex"]]
print("live body dword35 area:", " ".join("%08x" % v for v in live[30:40]))
for s, am in sorted(sinks.items()):
    if not am:
        continue
    mx = max(am)
    arr = [am.get(i, 0) for i in range(mx + 1)]
    # slide vs live body
    best = (0, None)
    for st in range(0, max(1, len(arr) - 44)):
        w = arr[st:st + 44]
        m = sum(1 for a, b in zip(w, live) if a == b)
        if m > best[0]:
            best = (m, st)
    print("sink %x: len %d best44 %d/44 @%s" % (s, mx + 1, best[0], best[1]))
