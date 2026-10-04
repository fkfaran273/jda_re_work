"""region_bitprof.py - bit-density profile of the per-call region vs the header.

The golden region dwords rise in popcount left->right (slice 104). Test whether
the region is Random3 draws MASKED into flag fields: for each golden dword,
find (draw, mask) with draw&mask == dword over the golden-second stream, and
check whether the masks form a structured ladder (e.g. sparse low bits in
early dwords, dense later). A structured mask ladder = region is
seeded-randomness shaped by the VM; random masks = not random at all.
"""
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import Random3

S = 1789240512
D4 = [0x00100400, 0x04144000, 0x8000C440, 0x88104C05,
      0x0025C852, 0xCC6E00B1, 0x01E76C80, 0x427BF58E]
EXTRA = {"W0": 0x13271271, "C1": 0xDB50F44C, "C2": 0xB63798CC,
         "C3": 0xDAB7F51A, "D2": 0xFB1A8296}

R = Random3(S)
st = [R.next() for _ in range(600)]

print("=== popcount profile (golden d4 + extras) ===")
for i, w in enumerate(D4):
    print("  d4[%d]=0x%08x pop=%2d" % (i, w, bin(w).count("1")))
for k, v in EXTRA.items():
    print("  %s=0x%08x pop=%2d" % (k, v, bin(v).count("1")))

print("\n=== mask-fit: dword = draw & mask for some draw in stream? ===")
for i, w in enumerate(D4):
    best = None
    for j, d in enumerate(st):
        if d & w == w:  # w's 1-bits are a subset of d's 1-bits
            best = (j, d)
            break
    print("  d4[%d]=0x%08x first-superset-draw idx=%s" % (i, w, best))
print("done")
