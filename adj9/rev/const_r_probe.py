"""const_r_probe.py - re-run const_diff batteries WITH canonical tiles + R column.

Prior runs (const_diff 1/2/3) used raw d0 words and had no R input, so they
could not see tag-mediated relations. Now inputs: H[8], sec (6 clean rows)
plus per-row R, Xhi, Xlo, RR; unknowns: W0, T0, T1, K02lo, d2, a[0..7].
Report: unknown == expr (direct), unknown == expr^K (constant key), for
xor/add/sub. Threshold: constant across all 6 rows, K != 0.
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
M = 0xFFFFFFFF
PH = {r["i"]: r for r in json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))}
CLEAN = (0, 1, 4, 5, 6, 7)
def canon(x):
    raw = bytes.fromhex(x["d0"])
    w = [int.from_bytes(raw[j:j+4], "big") for j in range(0, len(raw), 4)]
    for t in (w[1:5], w[5:9]):
        K13 = (t[3] ^ t[1]) & M
        R = (K13 >> 16) & 0xFFFF
        if (((t[2] ^ t[0]) & M) >> 16) & 0xFFFF == R:
            return w[0], list(t), R
    return w[0], list(w[1:5]), None
D = []
for i in CLEAN:
    r = PH[i]
    Hb = bytes.fromhex(r["H"])
    H = [int.from_bytes(Hb[j:j+4], "big") for j in range(0, 32, 4)]
    W0, t, R = canon(r)
    X = (t[0] ^ t[1]) & M
    K02 = (t[2] ^ t[0]) & M
    a = [int.from_bytes(bytes.fromhex(r["d4"])[j:j+4], "big") for j in range(0, 32, 4)]
    D.append({"i": i, "sec": r["second"], "H": H, "W0": W0, "T0": t[0], "T1": t[1],
              "K02lo": K02 & 0xFFFF, "d2": int(r["d2"], 16), "a": a, "R": R,
              "Xhi": (X >> 16) & 0xFFFF, "Xlo": X & 0xFFFF, "RR": ((R << 16) | R) & M})
UNK = [("W0", lambda r: r["W0"]), ("T0", lambda r: r["T0"]), ("T1", lambda r: r["T1"]),
       ("K02lo", lambda r: r["K02lo"]), ("d2", lambda r: r["d2"])] + \
      [("a%d" % k, lambda r, k=k: r["a"][k]) for k in range(8)]
E = []
for j in range(8):
    E.append(("H%d" % j, lambda r, j=j: r["H"][j]))
E += [("sec", lambda r: r["sec"]), ("R", lambda r: r["R"]),
      ("Xhi", lambda r: r["Xhi"]), ("Xlo", lambda r: r["Xlo"]), ("RR", lambda r: r["RR"])]
OPS = {"xor": lambda x, e: (x ^ e) & M, "add": lambda x, e: (x - e) & M, "sub": lambda x, e: (x + e) & M}
print("unknowns=%d exprs=%d rows=%d" % (len(UNK), len(E), len(D)))
for on, of in OPS.items():
    hits = []
    for an, af in UNK:
        xs = [af(r) for r in D]
        for en, ef in E:
            es = [ef(r) for r in D]
            ks = set(of(x, e) for x, e in zip(xs, es))
            if len(ks) == 1:
                K = ks.pop()
                if K == 0:
                    hits.append("EQUAL %s == %s" % (an, en))
                elif K != M:
                    hits.append("%s = %s %s K=%08x" % (an, en, on, K))
    print("--- op %s: %d hits ---" % (on, len(hits)))
    for h in hits[:20]:
        print("   " + h)
