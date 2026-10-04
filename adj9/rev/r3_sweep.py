"""r3_sweep.py - sweep ALL plausible (model, AR-shift) variants of the Bionic
random() sharing the Random3-tested seed schedule, against the golden region.

Random3 (= Bionic random/unix-time-seeded TYPE_3 LCG) is VERIFIED for the
16-byte header: make_header(S) matches 36/36 real blobs (2 devices). The golden
region misses in that stream, so test every nearby variant:
  models: raw-31bit draws; pair-XOR of consecutive draws; sum of pairs;
          draw&mask / draw|draw<<15 / draw^draw>>7 mixes (glibc-style halves)
  AR shifts: in case the region uses fewer/different warmup draws
  seeds: S, S-1, S+1, S-86400, S-19800 (IST offset), time_ms>>10?
Targets: W0, C1-C3, D2, d4 words 0-2.
"""
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import Random3

S = 1789240512
TARGETS = {"W0": 0x13271271, "C1": 0xDB50F44C, "C2": 0xB63798CC,
           "C3": 0xDAB7F51A, "D2": 0xFB1A8296,
           "d4w0": 0x00100400, "d4w1": 0x04144000, "d4w2": 0x8000C440}
SEEDS = [S, S - 1, S + 1, S - 86400, S + 86400, S - 19800, S + 19800,
         S // 1000, S >> 10, S & 0x7FFFFFFF]


def stream(seed, n=600):
    R = Random3(seed)
    return [R.next() for _ in range(n)]


def variants(st):
    V = {"raw": st}
    V["pairxor"] = [(st[i] ^ st[i + 1]) & 0xFFFFFFFF
                    for i in range(len(st) - 1)]
    V["pairsum"] = [(st[i] + st[i + 1]) & 0xFFFFFFFF
                    for i in range(len(st) - 1)]
    V["half"] = [((x & 0xFFFF) | ((y & 0xFFFF) << 16)) & 0xFFFFFFFF
                 for x, y in zip(st[::2], st[1::2])]
    V["halfswap"] = [((y & 0xFFFF) | ((x & 0xFFFF) << 16)) & 0xFFFFFFFF
                     for x, y in zip(st[::2], st[1::2])]
    V["shiftmix"] = [(x ^ (y >> 7)) & 0xFFFFFFFF
                     for x, y in zip(st[::2], st[1::2])]
    return V


print("targets: %s" % {k: "0x%08x" % v for k, v in TARGETS.items()})
hits = 0
for seed in SEEDS:
    st = stream(seed)
    for vn, seq in variants(st).items():
        for tn, tv in TARGETS.items():
            idx = [i for i, x in enumerate(seq) if x == tv]
            if idx:
                print("HIT seed=%d var=%s target=%s idx=%s"
                      % (seed, vn, tn, idx[:4]))
                hits += 1
print("total hits: %d" % hits)
print("done")
