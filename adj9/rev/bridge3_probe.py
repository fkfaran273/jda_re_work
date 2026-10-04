"""bridge3_probe.py - extend R/X bridge: K02lo, W0, d2, a[7]/a[5]/a[0..4].

Solved: K13=R||R, K02hi=R, a6=(R<<16)|Xlo, R==Xhi^Xlo (11/11).
Open: K02lo, W0, d2, a[0..5,7].
Tests per row (canon tiles, 11 rows):
 1. K02lo vs {Xhi,Xlo,R,W0lo,t0lo,t1lo,t2lo,t3lo,d2lo,a6lo} + xor-combos.
 2. W0 halves vs {R,Xhi,Xlo} + a[k] halves vs W0 halves.
 3. d2 full-word vs {a[k], a[k]^RR, W0^T0, T0^T1...}.
 4. a[7]/a[5] halves vs {R,Xhi,Xlo} (re-check with canon tiles).
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
            return w[0], list(t), R
    return w[0], list(w[1:5]), None
INFO = []
for i, x in enumerate(S):
    W0, t, R = canon(x)
    X = (t[0] ^ t[1]) & M
    K02 = (t[2] ^ t[0]) & M
    a = [int.from_bytes(bytes.fromhex(x["d4"])[j:j+4], "big") for j in range(0, 32, 4)]
    INFO.append({"i": i, "W0": W0, "t": t, "R": R, "X": X,
                 "Xhi": (X >> 16) & 0xFFFF, "Xlo": X & 0xFFFF,
                 "K02lo": K02 & 0xFFFF, "a": a, "d2": int(x["d2"], 16)})
W0a, ta, Ra = canon({"d0": A["d0"]})
Xa = (ta[0] ^ ta[1]) & M
K02a = (ta[2] ^ ta[0]) & M
aa = [int.from_bytes(bytes.fromhex(A["d4"])[j:j+4], "big") for j in range(0, 32, 4)]
INFO.append({"i": "app", "W0": W0a, "t": ta, "R": Ra, "X": Xa,
             "Xhi": (Xa >> 16) & 0xFFFF, "Xlo": Xa & 0xFFFF,
             "K02lo": K02a & 0xFFFF, "a": aa, "d2": int(A["d2"], 16)})
print("=== 1. K02lo battery ===")
cands = ["Xhi", "Xlo", "R", "W0lo", "t0lo", "t1lo", "t2lo", "t3lo", "d2lo", "a6lo", "Xhi^R", "Xlo^R"]
for nm in cands:
    n = 0
    for r in INFO:
        v = {"Xhi": r["Xhi"], "Xlo": r["Xlo"], "R": r["R"], "W0lo": r["W0"] & 0xFFFF,
             "t0lo": r["t"][0] & 0xFFFF, "t1lo": r["t"][1] & 0xFFFF,
             "t2lo": r["t"][2] & 0xFFFF, "t3lo": r["t"][3] & 0xFFFF,
             "d2lo": r["d2"] & 0xFFFF, "a6lo": r["a"][6] & 0xFFFF,
             "Xhi^R": (r["Xhi"] ^ r["R"]) & 0xFFFF,
             "Xlo^R": (r["Xlo"] ^ r["R"]) & 0xFFFF}[nm]
        if r["K02lo"] == v:
            n += 1
    print("  K02lo==%-6s %d/11%s" % (nm, n, "  <--" if n >= 9 else ""))
print("=== 2. W0 halves vs R/X ===")
for nm in ["R", "Xhi", "Xlo", "Xhi^R", "Xlo^R"]:
    mh = sum(1 for r in INFO if ((r["W0"] >> 16) & 0xFFFF) == ({"R": r["R"], "Xhi": r["Xhi"], "Xlo": r["Xlo"], "Xhi^R": (r["Xhi"] ^ r["R"]) & 0xFFFF, "Xlo^R": (r["Xlo"] ^ r["R"]) & 0xFFFF}[nm]))
    ml = sum(1 for r in INFO if (r["W0"] & 0xFFFF) == ({"R": r["R"], "Xhi": r["Xhi"], "Xlo": r["Xlo"], "Xhi^R": (r["Xhi"] ^ r["R"]) & 0xFFFF, "Xlo^R": (r["Xlo"] ^ r["R"]) & 0xFFFF}[nm]))
    print("  W0 hi==%s:%d/11 lo==%s:%d/11" % (nm, mh, nm, ml))
print("=== 3. d2 full-word vs a[k]/xor ===")
for k in range(8):
    n = sum(1 for r in INFO if r["d2"] == r["a"][k])
    if n:
        print("  d2==a[%d]: %d/11" % (k, n))
print("  (none above = d2 equals no a-word)")
RR = [((r["R"] << 16) | r["R"]) & M for r in INFO]
n = sum(1 for r, rr in zip(INFO, RR) if (r["d2"] ^ rr) & M in r["a"])
print("  d2^RR in a[]: %d/11" % n)
print("=== 4. a[7]/a[5] halves vs R/Xhi/Xlo ===")
for k in (7, 5, 0, 1, 2, 3, 4):
    for nm in ["R", "Xhi", "Xlo"]:
        mh = sum(1 for r in INFO if ((r["a"][k] >> 16) & 0xFFFF) == (r["R"] if nm == "R" else (r["Xhi"] if nm == "Xhi" else r["Xlo"])))
        ml = sum(1 for r in INFO if (r["a"][k] & 0xFFFF) == (r["R"] if nm == "R" else (r["Xhi"] if nm == "Xhi" else r["Xlo"])))
        if mh >= 9 or ml >= 9:
            print("  a[%d] hi==%s:%d lo==%s:%d <--" % (k, nm, mh, nm, ml))
print("  (no <-- lines = no other word carries R/X halves)")
