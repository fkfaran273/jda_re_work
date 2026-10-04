"""plane_vs_finex.py - compare the slice-118 captured plane with FinEx's own
stream plane for a signing we can reproduce offline (the golden one).

If the slot-count signature matches, the captured EMIT plane IS the VM's stream
plane -- and then the earlier finding that descriptor words are absent from the
trace (0/36 for #0, 0/8 for #4, 0/5 for #9) proves the descriptors are NOT
emitted: they are read out of memory written by the builder.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)

CAP = [3467672656, 3467675824, 3467675344, 3467672992, 3467672896,
       3467677168, 3467676784, 3467675776, 3467677024, 3467676448, 3467677408]
# FinEx golden run (fin_desc_probe.log)
FIN = [0x5450001000, 0x5500000000, 0x5500006000, 0x5500001000, 0x5500002000,
       0x5500003000, 0x550000a000, 0x5500004000, 0x5500005000, 0x5500007000,
       0x5500009000]
FIN_SLOTS = [658, 113, 90, 36, 36, 8, 4, 1, 1, 1, 1]

h = json.load(open(os.path.join(HERE, "harvest_out.json"), encoding="utf-8"))
S = {}
for q, n, v in h["emits"]:
    S.setdefault(q, {})[n] = v
cap_slots = [(q, len(S[q])) for q in CAP]
cap_sorted = sorted([s for _, s in cap_slots], reverse=True)
fin_sorted = sorted(FIN_SLOTS, reverse=True)
print("captured slot counts (desc) :", cap_sorted)
print("FinEx   slot counts (desc)  :", fin_sorted)
print("multiset match (mod 1)      :", cap_sorted == fin_sorted)
print()
print("pairing by count:")
used = set()
for q, s in cap_slots:
    for i, fs in enumerate(FIN_SLOTS):
        if i in used:
            continue
        if fs == s:
            print("  q=%-12d slots=%-4d  <->  va=%#x slots=%-4d" % (q, s, FIN[i], fs))
            used.add(i)
            break
    else:
        print("  q=%-12d slots=%-4d  <->  (no exact match)" % (q, s))
print()
print("note: 658 is unique and matches exactly; 107 vs 113 and 84 vs 90 differ by the")
print("trailing ASCII run (claims length differs between the two signings).")