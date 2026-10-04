"""a27bit_probe.py - a[2..7] (=bit columns 22..32) as ONE 176-bit integer?

If a[2..7] are consecutive 32-bit outputs of one generator, the six words
concatenated (BE) form a 192-bit (176 random + R-half) stream. Test:
  1. print a[2..7] as one hex string per row -- eyeball for counter/nonce runs
  2. a[k+1]-a[k] mod 2^32: small deltas would betray a counter/LCG
  3. shared bytes across rows at same offset (keystream reuse)?
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
M = 0xFFFFFFFF
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
A = json.load(open(os.path.join(HERE, "app_signings.json"), encoding="utf-8"))[0]
def words(h, n):
    raw = bytes.fromhex(h)
    return [int.from_bytes(raw[j:j+4], "big") for j in range(0, 4*n, 4)]
print("=== a[2..7] concatenated ===")
for i, x in enumerate(S):
    a = words(x["d4"], 8)[2:]
    print("  [%d] %s" % (i, "".join("%08x" % v for v in a)))
a = words(A["d4"], 8)[2:]
print("  [app] %s" % "".join("%08x" % v for v in a))
print()
print("=== consecutive-word deltas (a[k+1]-a[k]) ===")
for i, x in enumerate(S):
    a = words(x["d4"], 8)[2:]
    print("  [%d] %s" % (i, " ".join("%08x" % ((a[k+1]-a[k]) & M) for k in range(5))))
print()
print("=== same-offset byte sharing across rows (reuse?) ===")
strs = ["".join("%08x" % v for v in words(x["d4"], 8)[2:]) for x in S]
strs.append("".join("%08x" % v for v in words(A["d4"], 8)[2:]))
L = len(strs[0])
for pos in range(0, L, 2):
    by = [s[pos:pos+2] for s in strs]
    if len(set(by)) < len(by):
        from collections import Counter
        c = Counter(by)
        dup = {k: v for k, v in c.items() if v > 1}
        print("  bytepos %d: %s" % (pos // 2, dup))
print("  (no output above = no byte reused at the same offset across 11 rows)")
