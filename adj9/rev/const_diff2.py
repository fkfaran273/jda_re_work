"""const_diff2.py - extended constant-relationship search.

The builder XORs four words with a single key register, then stores 16 bytes
(`eor w8,w8,w22` x4 -> `eor v0.16b,v0.16b,v1.16b` -> `str q0`).  So each unknown
16-byte block is very likely  src ^ key  where src may itself combine H words.

For every unknown word X and every candidate expression E over H words -- single,
XOR of two, ADD of two, byte-reversed, rotated -- compute X ^ E per row and report
any (X, E) whose result is CONSTANT across rows (that is a proof + gives the key).
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


def rot(v, k):
    return ((v << k) | (v >> (32 - k))) & M


def rev(v):
    return int.from_bytes(v.to_bytes(4, "big"), "little")


D = []
for r in rows:
    Hb = bytes.fromhex(r["H"])
    d0 = be_words(r["d0"], 5)
    D.append({"H": [int.from_bytes(Hb[i:i + 4], "big") for i in range(0, 32, 4)],
              "W0": d0[0], "tile": d0[1:5], "d2": int(r["d2"], 16),
              "d4": be_words(r["d4"], 8)})

UNK = [("W0", lambda r: r["W0"])] + \
      [("tile%d" % k, lambda r, k=k: r["tile"][k]) for k in range(4)] + \
      [("#2", lambda r: r["d2"])] + \
      [("#4[%d]" % k, lambda r, k=k: r["d4"][k]) for k in range(8)]

# expressions over H words
E = []
for j in range(8):
    E.append(("H%d" % j, lambda r, j=j: r["H"][j]))
    E.append(("revH%d" % j, lambda r, j=j: rev(r["H"][j])))
    for k in (8, 16, 24):
        E.append(("rot%dH%d" % (k, j), lambda r, j=j, k=k: rot(r["H"][j], k)))
for j in range(8):
    for k in range(j + 1, 8):
        E.append(("H%d^H%d" % (j, k), lambda r, j=j, k=k: r["H"][j] ^ r["H"][k]))
        E.append(("H%d+H%d" % (j, k), lambda r, j=j, k=k: (r["H"][j] + r["H"][k]) & M))

print("unknowns=%d expressions=%d rows=%d" % (len(UNK), len(E), len(D)))
hits = 0
for an, af in UNK:
    xs = [af(r) for r in D]
    for en, ef in E:
        es = [ef(r) for r in D]
        keys = set((x ^ e) for x, e in zip(xs, es))
        if len(keys) == 1:
            K = keys.pop()
            if K != 0:
                print("  HIT  %-7s = %-10s ^ K   K=%08x" % (an, en, K))
                hits += 1
print("constant (X = E ^ K) hits: %d" % hits)

# also: does any unknown equal an expression directly (K=0)?
hits0 = 0
for an, af in UNK:
    xs = [af(r) for r in D]
    for en, ef in E:
        es = [ef(r) for r in D]
        if all(x == e for x, e in zip(xs, es)):
            print("  EQUAL %-7s == %s" % (an, en))
            hits0 += 1
print("direct-equality hits: %d" % hits0)