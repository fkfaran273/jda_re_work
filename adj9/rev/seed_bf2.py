"""seed_bf2.py - wider brute force: the region PRNG seed may be ANY clock near
the signing (ms/us truncated? ns? pid-mixed?), and the stream position of d0w0
is unknown. Instead of assuming, invert: for EACH sample, find ALL (seed,d2)
pairs where the observed d0w0/d0w4/d2 appear in a short stream; then intersect
positions across samples sharing a signing second.

Models: r3(seed=S), glibc(seed=S), r3(seed=S*1e3/ms?), splitmix64(seed=S)?
Also test: d0w0 = pid? tid? address low32? (heap/ASLR: varies per boot, but
det[0] vs det[2] same boot differ -> not boot-stable addresses... unless the
two mints ran in DIFFERENT processes: then ASLR differs and everything differs.
Check: are det[0]/det[2] same-process? Their C-triads differ too, so even the
'shared' triad is per-mint -> two separate nSign calls, maybe two processes.)
"""
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import Random3
import json
import struct

A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
G = [(s["d2"], struct.unpack(">I", bytes.fromhex(s["d0"])[:4])[0],
      struct.unpack(">I", bytes.fromhex(s["d0"])[16:20])[0]) for s in A]
print("golden d0w0/d0w4/d2:")
for d2, w0, w4 in G:
    print("  d2=%s w0=0x%08x (%d) w4=0x%08x (%d)" % (d2, w0, w0, w4, w4))

S = 1789240512
# 1) are w0 values < 2^31 (single-draw-able) or full 32-bit?
print("\nw0 > RAND_MAX(2^31-1)?", [(d2, w0 > 0x7FFFFFFF) for d2, w0, _ in G])
print("w4 > RAND_MAX?", [(d2, w4 > 0x7FFFFFFF) for d2, _, w4 in G])
# 2) w0 as (draw ^ draw>>k)? w0 = lo16(draw1)|hi16(draw2)?
R = Random3(S)
st = [R.next() for _ in range(200)]
print("\nstream[0:6]:", ["0x%08x" % x for x in st[:6]])
# 3) det0 w0=0x13271271=321327729: factor it (LCG back-solve needs mult inverse;
#    instead check: is w0 == (S*A+C)&M for common (A,C,M)?)
w0 = 0x13271271
print("\nw0=0x13271271 linear-fit attempts (w0 = (S*A+C)&M):")
import math
for nm, A_, C_, M_ in (("glibc", 1103515245, 12345, 2**31),
                       ("msvc", 214013, 2531011, 2**32),
                       ("park-miller-direct", 16807, 0, 2**31 - 1),
                       ("bionic64", 6364136223846793005, 1, 2**64)):
    print("  %-18s -> 0x%x (want 0x13271271) %s"
          % (nm, (S * A_ + C_) % M_, "HIT" if (S * A_ + C_) % M_ == w0 else ""))
print("done")
