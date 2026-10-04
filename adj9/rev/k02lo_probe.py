"""k02lo_probe.py - what is K02lo = (T2^T0) low16?

K02hi == R is solved (11/11). K02lo is the remaining tile unknown.
Test K02lo against {Xhi, Xlo, R, W0lo, t0lo, t1lo, d2lo, a6lo} and
xor-combos, over all 11 rows (canonical tiles).
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
M = 0xFFFFFFFF
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
A = json.load(open(os.path.join(HERE, "app_signings.json"), encoding="utf-8"))[0]
def canon(x):
    raw = bytes.fromhex(x["d0"])
    w = [int.from_bytes(raw[j:j+4], "big") for j in range(0, len(raw), 4)]
    for t in (w[1:5], w[5:9]):
        K13 = (t[3] ^ t[1]) & M
        R = (K13 >> 16) & 0xFFFF
        if (((t[2] ^ t[0]) & M) >> 16) & 0xFFFF == R:
            return w[0], t, R
    return w[0], w[1:5], None
ROWS = [(i, x["d0"], x["d2"], x["d4"]) for i, x in enumerate(S)]
ROWS.append(("app", A["d0"], A["d2"], A["d4"]))
INFO = []
for i, d0, d2, d4 in ROWS:
    W0, t, R = canon({"d0": d0})
    X = (t[0] ^ t[1]) & M
    K02 = (t[2] ^ t[0]) & M
    a = [int.from_bytes(bytes.fromhex(d4)[j:j+4], "big") for j in range(0, 32, 4)]
    INFO.append({"i": i, "R": R, "X": X, "Xhi": (X >> 16) & 0xFFFF, "Xlo": X & 0xFFFF,
                 "W0": W0, "t": t, "K02lo": K02 & 0xFFFF, "d2": int(d2, 16),
                 "a6lo": a[6] & 0xFFFF, "a": a})
print("row: K02lo vs candidates")
for r in INFO:
    print("  [%-3s] K02lo=%04x Xhi=%04x Xlo=%04x R=%04x W0lo=%04x t0lo=%04x t1lo=%04x d2lo=%04x a6lo=%04x" % (
        r["i"], r["K02lo"], r["Xhi"], r["Xlo"], r["R"], r["W0"] & 0xFFFF,
        r["t"][0] & 0xFFFF, r["t"][1] & 0xFFFF, r["d2"] & 0xFFFF, r["a6lo"]))
print()
print("equality battery: K02lo == candidate?")
cands = ["Xhi", "Xlo", "R", "W0lo", "t0lo", "t1lo", "t2lo", "t3lo", "d2lo", "a6lo", "Xhi^R", "Xlo^R"]
for nm in cands:
    n = 0
    for r in INFO:
        v = {"Xhi": r["Xhi"], "Xlo": r["Xlo"], "R": r["R"], "W0lo": r["W0"] & 0xFFFF,
             "t0lo": r["t"][0] & 0xFFFF, "t1lo": r["t"][1] & 0xFFFF,
             "t2lo": r["t"][2] & 0xFFFF, "t3lo": r["t"][3] & 0xFFFF,
             "d2lo": r["d2"] & 0xFFFF, "a6lo": r["a6lo"],
             "Xhi^R": (r["Xhi"] ^ r["R"]) & 0xFFFF,
             "Xlo^R": (r["Xlo"] ^ r["R"]) & 0xFFFF}[nm]
        if r["K02lo"] == v:
            n += 1
    flag = "  <--" if n >= 9 else ""
    print("  K02lo==%-6s %d/11%s" % (nm, n, flag))
