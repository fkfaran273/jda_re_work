"""_inv2_ver3.py — full law verification + table/KB/permutation extraction."""
import gzip
import json
import sys
from collections import Counter, defaultdict

TOP = 620

fn = sys.argv[1] if len(sys.argv) > 1 else "_inv2_row7_real.json.gz"
A = json.load(gzip.open(fn, "rt"))
wire = A["wire"]
ops = [(e[0], e[1], (e[3] + e[4]) if e[0] == "E" else (TOP + e[4]),
        e[5] & 0xFFFFFFFF)
       for e in wire if e[2] == 0x5450001000 and e[0] in ("E", "Q")]

state = {}
qwin = []
ok = defaultdict(int)
bad = defaultdict(int)
sw_read = []
tbl_snaps = []
diag1 = []

for (kind, pc, o, v) in ops:
    if kind == "Q":
        qwin.append((o, state.get(o, 0), v & 0xFFFFFFFF))
        continue
    v &= 0xFF
    pv = state.get(o, 0)
    taps = [t for t in qwin if t[0] != o]
    if pc == 0x111c68 and len(taps) == 1:
        k = v ^ pv ^ taps[0][2]
        if k == 0x55:
            ok["sweep"] += 1
        else:
            bad["sweep"] += 1
        sw_read.append((o, taps[0][0], taps[0][2]))
    elif pc == 0x111f70:
        tv = state.get(621 + pv)
        if tv is not None and (tv ^ 0x55) == v:
            ok["skt"] += 1
        else:
            bad["skt"] += 1
        tbl_snaps.append(tuple(state.get(621 + i, 0) for i in range(256)))
    elif pc in (0x10daa0, 0x10dc08, 0x10dd70, 0x10de2c, 0x10e040, 0x10e0fc,
                0x10e310, 0x10e3cc, 0x10e5e0, 0x10e748, 0x10e8b0):
        diag1.append((pc, o, pv, v, tuple((t[0], t[1]) for t in taps)))
    state[o] = v
    qwin = []

print("ok:", dict(ok), "bad:", dict(bad))
kbs = [p for (_, p, _) in sw_read]
print("sweeps:", len(sw_read), "KB abs min/max:", min(kbs), max(kbs))
starts = [i for i, (o, p, vv) in enumerate(sw_read) if p == 877]
print("KB restarts at sweep idx:", starts[:12], "(count %d)" % len(starts))
print("distinct table snapshots:", len(set(tbl_snaps)))
T = tbl_snaps[0]
print("T[0:32] :", " ".join("%02x" % b for b in T[:32]))
print("T perm  :", len(set(T)) == 256)

pure = imp = 0
perm = {}
for (pc, o, pv, v, srcs) in diag1:
    m = [a for (a, b) in srcs if b == v]
    if m:
        pure += 1
        perm.setdefault(o % 16, set()).add(m[-1] % 16)
    else:
        imp += 1
print("diag-1 events:", len(diag1), "pure copies:", pure, "impure:", imp)
pm = {k: sorted(vv) for k, vv in sorted(perm.items())}
print("perm dst%16 -> src%16:", pm)
