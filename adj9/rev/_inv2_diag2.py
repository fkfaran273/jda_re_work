"""_inv2_diag2.py — fit the 4 diagonal-site laws from queue PUSH/POP operands."""
import gzip
import json
import sys
from collections import Counter, defaultdict

TOP = 620
DIAG2 = (0x10d0ec, 0x110e30, 0x10a5fc, 0x10fbf4)
DIAG1 = (0x10daa0, 0x10dc08, 0x10dd70, 0x10de2c, 0x10e040, 0x10e0fc,
         0x10e310, 0x10e3cc, 0x10e5e0, 0x10e748, 0x10e8b0, 0x10c4d8)

fn = sys.argv[1] if len(sys.argv) > 1 else "_inv2_row7_real.json.gz"
A = json.load(gzip.open(fn, "rt"))
wire = A["wire"]

# chronological: queue ops (PUSH/POP with values) + MAIN E ops
seq = []
for e in wire:
    if e[0] in ("PUSH", "POP"):
        seq.append((e[0], e[1], e[2] & 0xFFFFFFFFFFFF, e[3] & 0xFFFFFFFF))
    elif e[0] == "E" and (e[2] & 0xFFFFFFFFFFFF) == 0x5450001000:
        seq.append(("E", e[1], e[3] + e[4], e[5] & 0xFF))

# for each diag-2 E: the PUSH/POP values since the previous E
ops_site = defaultdict(list)
qops = []
for (kind, pc, a, v) in seq:
    if kind == "E":
        if pc in DIAG2:
            pops = [vv for (k, _, _, vv) in qops if k == "POP"]
            pushs = [vv for (k, _, _, vv) in qops if k == "PUSH"]
            ops_site[pc].append((a, v, pops, pushs))
        qops = []
    else:
        qops.append((kind, pc, a, v))

for pc in DIAG2:
    samples = ops_site[pc]
    print("site %#x: %d samples" % (pc, len(samples)))
    print("  first 3 pops:", [("%d:%s" % (a, "%02x" % v))
                              for (a, v, p, s) in samples[:3]]
          )
    print("  pops[0]:", ["%08x" % x for x in samples[0][2]][:12])
    print("  pops[1]:", ["%08x" % x for x in samples[1][2]][:12])
    print("  pops[2]:", ["%08x" % x for x in samples[2][2]][:12])
