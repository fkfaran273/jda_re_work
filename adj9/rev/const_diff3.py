"""const_diff3.py - relationships AMONG the unknowns.

The builder does `out[4 words] = src[4 words] ^ K` with a per-site key.  If the *same*
key (or the same keystream phase) is applied to several words of one signing, then the
XOR of two unknowns is CONSTANT across rows (= XOR of the two plaintexts).  Finding such
a pair both proves the structure and hands us the plaintext relation, which can then be
matched against libsigner.so's rodata constants.

Tests every pair among {W0, tile0..3, #2, #4[0..7]} under XOR / ADD / SUB, over the 6
clean rows, and reports constant differences (and whether a single key covers everything).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
M = 0xFFFFFFFF
rows = [r for r in json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))
        if r["H"] and r["i"] in (0, 1, 4, 5, 6, 7)]


def be_words(hexs, n):
    raw = bytes.fromhex(hexs)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 4 * n, 4)]


D = []
for r in rows:
    d0 = be_words(r["d0"], 5)
    D.append({"W0": d0[0], "tile": d0[1:5], "d2": int(r["d2"], 16),
              "d4": be_words(r["d4"], 8)})

L = [("W0", lambda r: r["W0"])] + \
    [("tile%d" % k, lambda r, k=k: r["tile"][k]) for k in range(4)] + \
    [("#2", lambda r: r["d2"])] + \
    [("#4[%d]" % k, lambda r, k=k: r["d4"][k]) for k in range(8)]
vals = [(n, [f(r) for r in D]) for n, f in L]

print("labels: %d   rows: %d" % (len(L), len(D)))
print()
print("--- pairwise constancy (all %d pairs x 3 ops) ---" % (len(L) * (len(L) - 1) // 2))
hits = []
for i in range(len(vals)):
    for j in range(i + 1, len(vals)):
        an, av = vals[i]
        bn, bv = vals[j]
        for on, of in (("xor", lambda a, b: (a ^ b) & M),
                       ("add", lambda a, b: (a - b) & M),
                       ("sub", lambda a, b: (a - b) & M)):
            ds = set(of(a, b) for a, b in zip(av, bv))
            if len(ds) == 1:
                hits.append((an, bn, on, ds.pop()))
print("constant pairs: %d" % len(hits))
for an, bn, on, K in hits:
    print("   %-8s %-3s %-8s = %08x  (constant)" % (an, on, bn, K))

print()
print("--- is there ONE key K such that every unknown = const ^ K ? ---")
# if so, the pairwise XORs above would all be constant AND consistent with fixed plaintexts
base = vals[0][1]
for Kname, Kv in (("W0", vals[0][1]),):
    keys = []
    for r in range(len(D)):
        keys.append(Kv[r])
    print("   per-row W0:", ["%08x" % k for k in keys])
    # test: all unknowns XOR W0 constant?
    cst = []
    for n, v in vals:
        ds = set((a ^ b) & M for a, b in zip(v, Kv))
        cst.append((n, len(ds) == 1, ds.pop() if len(ds) == 1 else None))
    ok = [c for c in cst if c[1]]
    print("   unknowns with constant XOR vs W0: %d/%d" % (len(ok), len(cst)))
    for n, _, K in ok:
        print("      %-8s = plaintext %08x ^ W0" % (n, K))