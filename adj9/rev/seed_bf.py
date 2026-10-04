"""seed_bf.py - brute-force WHICH time value seeds the region PRNG.

Fact: det[0] and det[2] share created_at=21:15:11.678 but DIFFER in every
region dword (d0w0/d0w4/d2/d4). So the seed is NOT created_at-derived, and NOT
map-derived (same payload) -> it must be a FRESHER clock: the signing instant
(time(NULL) at nSign, second resolution) or finer (ms/us).

We know det[0..2] were signed within ~84ms of each other (created .678/.762).
Their signing seconds S0,S1,S2 are each in {T, T+1} for T = unix(21:15:11 IST).
For each candidate PRNG model (Random3/BSD-TYPE3 with seed=S; glibc LCG with
seed=S; xorshift(maskSeq)-style), test whether the observed d0w0 values sit at
the SAME stream position across the 13 samples (positional consistency = the
model is right, only the offset unknown).
"""
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import Random3
import json
import struct

A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
D = json.load(open(os.path.join(HERE, "det_full.json"), encoding="utf-8"))

samples = []
for s in A:
    w = struct.unpack(">36I", bytes.fromhex(s["d0"]))
    samples.append(("als", s["d2"], w[0], w[4], s["d4"][:16]))
for s in D:
    w = struct.unpack(">36I", bytes.fromhex(s["d0"]))
    d2 = "%08x" % s["d2"] if isinstance(s["d2"], int) else s["d2"]
    samples.append(("det", d2, w[0], w[4], s["d4"][:16]))
print("samples: %d" % len(samples))


def r3_stream(seed, n=40):
    R = Random3(seed)
    return [R.next() for _ in range(n)]


def glibc_stream(seed, n=40):
    s = seed & 0x7FFFFFFF
    out = []
    for _ in range(n):
        s = (1103515245 * s + 12345) & 0x7FFFFFFF
        out.append(s)
    return out


# candidate signing seconds: 2026-09-12 21:15:11 IST = 15:45:11 UTC?
# compute properly: created_at ...+0200 means UTC+2. 21:15:11+0200 = 19:15:11Z
import datetime
base = int(datetime.datetime(2026, 9, 12, 19, 15, 11,
                             tzinfo=datetime.timezone.utc).timestamp())
print("base unix:", base)
CANDS = [base - 19800 + k for k in range(-3, 6)]  # IST = UTC+5:30 => 19800
CANDS += [base + k for k in range(-3, 6)]
print("cand secs:", CANDS)

for name, fn in (("r3", r3_stream), ("glibc", glibc_stream)):
    print("\n=== model %s: positional consistency of d0w0 ===" % name)
    for sd in CANDS[:6]:
        st = fn(sd)
        pos = {}
        for tag, d2, w0, w4, d4h in samples:
            idx = [i for i, x in enumerate(st) if x == w0]
            if idx:
                pos.setdefault(tuple(idx[:2]), []).append(d2)
        if pos:
            print("  seed=%d: %s" % (sd, {k: len(v) for k, v in pos.items()}))
print("done")
