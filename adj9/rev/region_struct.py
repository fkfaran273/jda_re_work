# region_struct.py - WHAT IS the #0/#2/#4 region? How much of it is per-call?
#
# "we need to find #0/#2/#4 region" - so characterise it across every sample we
# have: the golden descriptors, the 3 segmented signings, and the 10 recorded
# signings. For each slot, find the fixed part and the varying part, so the size
# of the real unknown is known exactly.
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
FD = json.load(open(os.path.join(HERE, "fin_descs.json"), encoding="utf-8"))
DET = json.load(open(os.path.join(HERE, "desc_det_result.json"), encoding="utf-8"))


def be(vs):
    return b"".join(struct.pack(">I", v & 0xffffffff) for v in vs)


S = []
for d in FD["descs"]:
    if d["build_idx"] == 0:
        d0 = bytes.fromhex(d["data_hex"])
    if d["build_idx"] == 2:
        d2 = int(d["data_hex"], 16)
    if d["build_idx"] == 4:
        d4 = bytes.fromhex(d["data_hex"])
S.append(("golden", d0, d2, d4))
for i, e in enumerate(DET):
    S.append(("det[%d]" % i, be(e["d0"]), e["d2"], be(e["d4"])))
try:
    ALS = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
    for i, s in enumerate(ALS):
        if s.get("d4"):
            S.append(("als[%d]" % i, bytes.fromhex(s["d0"]) if s.get("d0") else None,
                      int(s["d2"], 16), bytes.fromhex(s["d4"])))
except Exception as e:
    print("als: %s" % e)

print("samples: %d" % len(S))
print("\n=== #0 (144 B = 36 dwords) as 9 groups of 4 ===")
for t, d0, _, _ in S:
    if not d0:
        continue
    w = struct.unpack(">36I", d0[:144])
    print("  %-9s" % t)
    for g in range(9):
        quad = w[g * 4:g * 4 + 4]
        print("      g%d  %s" % (g, " ".join("%08x" % x for x in quad)))

print("\n=== per-dword constancy across samples ===")
d0s = [d0 for _, d0, _, _ in S if d0]
n = len(d0s)
const, vary = [], []
for i in range(36):
    vals = {struct.unpack(">36I", b[:144])[i] for b in d0s}
    (const if len(vals) == 1 else vary).append(i)
print("  #0 dwords constant in all %d samples: %s" % (n, const))
print("  #0 dwords that VARY: %s" % vary)
if const:
    c = struct.unpack(">36I", d0s[0][:144])
    print("  constant values: %s" % " ".join("%08x" % c[i] for i in const))

print("\n=== #4 (32 B = 8 dwords) ===")
d4s = [(t, d4) for t, _, _, d4 in S]
for t, d4 in d4s:
    print("  %-9s %s" % (t, d4.hex()))
print("  distinct #4 values: %d/%d" % (len({d4 for _, d4 in d4s}), len(d4s)))
for i in range(8):
    vals = {struct.unpack(">8I", d4)[i] for _, d4 in d4s}
    print("    dw%d: %d distinct %s" % (i, len(vals),
                                        "CONSTANT %08x" % vals.pop() if len(vals) == 1
                                        else ""))

print("\n=== #2 (1 dword) ===")
d2s = [(t, d2) for t, _, d2, _ in S]
for t, d2 in d2s:
    print("  %-9s %08x" % (t, d2))
print("  distinct #2: %d/%d" % (len({d2 for _, d2 in d2s}), len(d2s)))

print("\n=== do #0's varying dwords equal #2 or #4 dwords? ===")
for t, d0, d2, d4 in S:
    if not d0:
        continue
    w = struct.unpack(">36I", d0[:144])
    q = struct.unpack(">8I", d4)
    hits = [i for i in range(36) if w[i] in (d2,) + q]
    print("  %-9s #2/#4 values inside #0 at dword index: %s" % (t, hits))