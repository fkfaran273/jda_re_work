"""lcg_probe.py - linear / time-lowbits structure in W0/tile/#2/#4.

Tests on the 6 clean rows (pair_h3) + app row (no H, time only):
 1. W0 vs nsign_ts low32 / low31 / (ts%1000): exact equality?
 2. tile[k+1] vs tile[k]: per-row delta / xor (is the tile an LCG walk)?
 3. #2 vs W0/tile/second: add/sub/xor deltas printed (eyeball linear fits)?
 4. #4[0] (sparse bitfield) vs claims_len (#7) and second: table.
 5. W0 ordered by second: deltas between consecutive signings.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
M = 0xFFFFFFFF
R = [r for r in json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))
     if r["H"] and r["i"] in (0, 1, 4, 5, 6, 7)]
R = sorted(R, key=lambda r: r["second"])
A = json.load(open(os.path.join(HERE, "app_signings.json"), encoding="utf-8"))[0]


def be(hexs, n):
    raw = bytes.fromhex(hexs)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 4 * n, 4)]


print("--- 1. W0 vs nsign_ts low bits ---")
for r in R:
    w0 = be(r["d0"], 1)[0]
    ts = r["nsign_ts"]
    print("  [%d] W0=%08x ts=%d lo32=%08x eq=%s lo31eq=%s msec=%d" %
          (r["i"], w0, ts, ts & M, w0 == (ts & M), w0 == (ts & 0x7FFFFFFF), ts % 1000))
w0a = be(A["d0"], 1)[0]
print("  [app] W0=%08x sec=%d (no ts)" % (w0a, A["second"]))

print()
print("--- 2. intra-tile steps (tile0->1->2->3) ---")
for r in R:
    t = be(r["d0"], 5)[1:5]
    dx = ["%08x" % ((t[k + 1] - t[k]) & M) for k in range(3)]
    xx = ["%08x" % (t[k + 1] ^ t[k]) for k in range(3)]
    print("  [%d] tile=%s add=%s xor=%s" %
          (r["i"], ["%08x" % v for v in t], dx, xx))
ta = be(A["d0"], 5)[1:5]
print("  [app] tile=%s" % (["%08x" % v for v in ta]))

print()
print("--- 3. #2 vs W0 / tile0 / second ---")
for r in R:
    w0 = be(r["d0"], 1)[0]
    t0 = be(r["d0"], 5)[1]
    d2 = int(r["d2"], 16)
    print("  [%d] #2=%08x #2^W0=%08x #2-W0=%08x #2^t0=%08x #2^sec=%08x" %
          (r["i"], d2, d2 ^ w0, (d2 - w0) & M, d2 ^ t0, d2 ^ (r["second"] & M)))

print()
print("--- 4. #4[0] vs claims_len / second ---")
for r in R:
    a0 = be(r["d4"], 1)[0]
    print("  [%d] #4[0]=%08x claims_len=%d sec=%d" % (r["i"], a0, int(r["d7"], 16) if "d7" in r else -1, r["second"]))
print("  [app] #4[0]=%s claims=360 sec=%d" % (A["d4"][:8], A["second"]))

print()
print("--- 5. W0 ordered by second (deltas) ---")
prev = None
for r in R:
    w0 = be(r["d0"], 1)[0]
    if prev is not None:
        print("  %d -> %d  dsec=%d dW0=%08x xW0=%08x" %
              (prev[0], r["i"], r["second"] - prev[1], (w0 - prev[2]) & M, w0 ^ prev[2]))
    prev = (r["i"], r["second"], w0)
