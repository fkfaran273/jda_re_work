"""_inv2_ver.py v2 — single-pass law verification with running state."""
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
sw_read = []          # (sweep abs, KB abs, KB val)
tbl_before = []       # table snapshot right before each SKT write
diag1 = []            # (pc, dst abs, src abs, src val, dst pre, v)
diag2 = []            # (block start, in-tuple, out-tuple)
cur_blk_in = None
blk_in = {}
blk_out = {}
tbl = None            # last completed table snapshot
tbl_snaps = set()
pending_diag1 = {}

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
            if bad["sweep"] < 3:
                print("sweep bad @%d pre=%02x v=%02x tap=%02x@%d"
                      % (o, pv, v, taps[0][2], taps[0][0]))
        sw_read.append((o, taps[0][0], taps[0][2]))
    elif pc == 0x111f70:
        tv = state.get(621 + pv)
        if tv is not None and (tv ^ 0x55) == v:
            ok["skt"] += 1
        else:
            bad["skt"] += 1
            if bad["skt"] < 3:
                print("skt bad @%d cur=%02x v=%02x T=%s" % (o, pv, v, tv))
        if tbl is not None and len(tbl) == 256:
            tbl_snaps.add(tuple(tbl[i] for i in range(621, 877)))
        tbl = None
    elif pc in (0x10daa0, 0x10dc08, 0x10dd70, 0x10de2c, 0x10e040, 0x10e0fc,
                0x10e310, 0x10e3cc, 0x10e5e0, 0x10e748, 0x10e8b0):
        srcs = [(t[0], t[1]) for t in taps]
        diag1.append((pc, o, pv, v, srcs))
    elif pc in (0x10d0ec, 0x110e30, 0x10a5fc, 0x10fbf4):
        blk_in[o] = pv
        pending_diag1 = None
    elif pc == 0x10c4d8 and o == 621:
        tbl = {621: v}
    elif pc == 0x10c3b4 and tbl is not None and 622 <= o < 877:
        tbl[o] = v
        if len(tbl) == 256:
            pass
    state[o] = v
    qwin = []

print("ok:", dict(ok), "bad:", dict(bad))
print("sweeps:", len(sw_read))
kbs = [p for (_, p, _) in sw_read]
print("KB abs progression (first 40):", kbs[:40])
print("KB abs min/max:", min(kbs), max(kbs))
tbl_list = sorted(tbl_snaps)
print("distinct table snapshots:", len(tbl_list))
T = tbl_list[0]
print("T[0:32]:", " ".join("%02x" % b for b in T[:32]))
print("permutation:", len(set(T)) == 256)

# diag-1 permutation: for each (pc,dst): find src == the tap whose value chain
# matches; build position map from the data (src val == dst pre? etc.)
print("\ndiag-1 samples (first 14):")
for d in diag1[:14]:
    print("  pc=%#x dst=%d pre=%02x v=%02x srcs=%s"
          % (d[0], d[1], d[2], d[3], [(a, "%02x" % b) for a, b in d[4]]))
