"""const_diff.py - solve for the builder's arithmetic directly.

We have 6 clean rows with (H, second, claims) and the unknown words
(W0, tile[4], #2, plus #4's 8 words).  If any unknown word is a *simple* function
of an H word or of `second` -- XOR, ADD or SUB -- then the difference is the SAME
CONSTANT in every row.  So: compute those differences across rows and report any
pair that is constant (and non-trivial).

A constant difference is a proof of the relationship (and hands us the constant,
which can then be looked up in libsigner.so's data).
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)

M = 0xFFFFFFFF
rows = json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))
rows = [r for r in rows if r["H"] and r["i"] in (0, 1, 4, 5, 6, 7)]
print("clean rows: %s" % [r["i"] for r in rows])


def be_words(hexs, n):
    raw = bytes.fromhex(hexs)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 4 * n, 4)]


data = []
for r in rows:
    Hb = bytes.fromhex(r["H"])
    H = [int.from_bytes(Hb[i:i + 4], "big") for i in range(0, 32, 4)]
    d0 = be_words(r["d0"], 5)
    data.append({
        "i": r["i"], "sec": r["second"], "H": H,
        "W0": d0[0], "tile": d0[1:5],
        "d2": int(r["d2"], 16), "d4": be_words(r["d4"], 8),
        "d0_all": be_words(r["d0"], 36),
    })

# label sets to compare
A = []          # (label, fn(row) -> value)
A.append(("W0", lambda r: r["W0"]))
for k in range(4):
    A.append(("tile%d" % k, lambda r, k=k: r["tile"][k]))
A.append(("#2", lambda r: r["d2"]))
for k in range(8):
    A.append(("#4[%d]" % k, lambda r, k=k: r["d4"][k]))
# every distinct word of #0 (it repeats, so this covers the same values)
for k in range(36):
    A.append(("#0[%d]" % k, lambda r, k=k: r["d0_all"][k]))

B = [("H[%d]" % k, lambda r, k=k: r["H"][k]) for k in range(8)]
B.append(("sec", lambda r: r["sec"]))
B.append(("sec_be1", lambda r: r["sec"] + 1))
B.append(("sec-1", lambda r: r["sec"] - 1))

OPS = {
    "xor": lambda a, b: (a ^ b) & M,
    "add": lambda a, b: (a - b) & M,
    "sub": lambda a, b: (a + b) & M,
}

print()
print("--- constant-relationship search over %d rows ---" % len(data))
hits = []
for an, af in A:
    va = [af(r) for r in data]
    for bn, bf in B:
        vb = [bf(r) for r in data]
        for on, of in OPS.items():
            ds = [of(a, b) for a, b in zip(va, vb)]
            if len(set(ds)) == 1 and ds[0] not in (0, M):
                hits.append((an, on, bn, ds[0]))
            elif len(set(ds)) == 1 and ds[0] == 0:
                hits.append((an, on + "(equal)", bn, 0))
print("constant pairs found: %d" % len(hits))
for an, on, bn, K in hits[:60]:
    print("   %-9s = %-15s %-8s  K=%08x" % (an, bn, on, K))

# also: is an unknown word constant across rows?
print()
print("--- per-label constancy across rows ---")
for an, af in A[:14]:
    vs = [af(r) for r in data]
    print("   %-9s distinct=%-2d %s" % (an, len(set(vs)), ["%08x" % v for v in vs[:3]]))