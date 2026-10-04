"""_inv2_fit2.py — subset-XOR/ADD fit of the 4 diagonal-site laws (full pops)."""
import gzip
import json
import sys
from collections import defaultdict
from itertools import combinations

TOP = 620
DIAG2 = (0x10d0ec, 0x110e30, 0x10a5fc, 0x10fbf4)

fn = sys.argv[1] if len(sys.argv) > 1 else "_inv2_row7_real.json.gz"
A = json.load(gzip.open(fn, "rt"))
wire = A["wire"]

seq = []
for e in wire:
    if e[0] in ("PUSH", "POP"):
        seq.append((e[0], e[1], e[2] & 0xFFFFFFFFFFFF, e[3] & 0xFFFFFFFF))
    elif e[0] == "E" and (e[2] & 0xFFFFFFFFFFFF) == 0x5450001000:
        seq.append(("E", e[1], e[3] + e[4], e[5] & 0xFF))

ops_site = defaultdict(list)
qops = []
for (kind, pc, a, v) in seq:
    if kind == "E":
        if pc in DIAG2:
            pops = [vv for (k, _, _, vv) in qops if k == "POP"]
            ops_site[pc].append((a, v, pops))
        qops = []
    else:
        qops.append((kind, pc, a, v))

for pc in DIAG2:
    samples = ops_site[pc]
    print("site %#x: %d samples" % (pc, len(samples)))
    s0 = samples[0]
    print("  full pops[0]:", ["%08x" % x for x in s0[2]])
    # candidate operand slots: fixed across samples? print pop-count histogram
    cnts = Counter(len(s[2]) for s in samples)
    print("  pop-count histogram:", dict(cnts))
    npop = cnts.most_common(1)[0][0]
    ss = [s for s in samples if len(s[2]) == npop]
    print("  using %d samples with npop=%d" % (len(ss), npop))
    # subset-XOR fit over byte-valued pops
    byte_idx = [i for i in range(npop) if all(s[2][i] < 0x100 for s in ss)]
    print("  byte-valued pop slots:", byte_idx)
    best = None
    for r in range(1, min(6, len(byte_idx)) + 1):
        found = []
        for combo in combinations(byte_idx, r):
            if all((s[2][combo[0]] ^ s[2][combo[1]] if len(combo) == 2 else
                    __import__("functools").reduce(
                        lambda x, y: x ^ y, (s[2][i] for i in combo))) ==
                   (s[1] & 0xFF) for s in ss[:40]):
                found.append(combo)
        if found:
            # verify on all
            good = []
            for combo in found:
                ok = all((__import__("functools").reduce(
                    lambda x, y: x ^ y, (s[2][i] for i in combo))) ==
                    (s[1] & 0xFF) for s in ss)
                if ok:
                    good.append(combo)
            print("  XOR-fit combos (verified all %d): %s"
                  % (len(ss), good[:6]))
            best = good
            break
        if r >= 6:
            break
    if not best:
        # try last-pop transforms
        laws = Counter()
        for s in ss:
            last = s[2][-1] & 0xFF
            v = s[1] & 0xFF
            laws[("xor", last ^ v)] += 1
            laws[("add", (v - last) & 0xFF)] += 1
        print("  no XOR subset fit; last-pop deltas:", laws.most_common(4))
