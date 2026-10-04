"""str_probe.py - the tile words are NOT independent: constrain harder.

Solved relations (11/11): K13 = R||R, K02hi = R, a6 = (R<<16)|Xlo,
R == Xhi ^ Xlo. Remaining tile unknowns: T0, T1 (T3 = T1^RR, T2 = T0^K02).
Test, over all 11 rows (canon tiles):
  1. T1 vs T0: is T1 = f(T0) for row-independent f? (add/xor/rot constancy)
  2. Is T0 (or T1) == a[k] for some k? (tile base sitting inside d4?)
  3. Is T0 (or T1) == d2? Is W0 == a[k]?
  4. H halves (6 clean rows): does any H-half equal R, Xhi, Xlo?
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
M = 0xFFFFFFFF
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
A = json.load(open(os.path.join(HERE, "app_signings.json"), encoding="utf-8"))[0]
PH = {r["i"]: r for r in json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))}
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
    a = [int.from_bytes(bytes.fromhex(x["d4"])[j:j+4], "big") for j in range(0, 32, 4)]
    X = (t[0] ^ t[1]) & M
    INFO.append({"i": i, "W0": W0, "t": t, "R": R, "X": X, "a": a,
                 "d2": int(x["d2"], 16),
                 "H": bytes.fromhex(PH[i]["H"]) if i in PH and PH[i].get("H") else None})
W0a, ta, Ra = canon({"d0": A["d0"]})
aa = [int.from_bytes(bytes.fromhex(A["d4"])[j:j+4], "big") for j in range(0, 32, 4)]
INFO.append({"i": "app", "W0": W0a, "t": ta, "R": Ra, "X": (ta[0] ^ ta[1]) & M,
             "a": aa, "d2": int(A["d2"], 16), "H": None})
print("=== 1. T1 vs T0 constancy (xor/add/sub/rot) ===")
for nm, fn in [("xor", lambda a, b: (a ^ b) & M), ("add", lambda a, b: (a - b) & M),
               ("sub", lambda a, b: (a + b) & M)]:
    ds = set(fn(r["t"][1], r["t"][0]) for r in INFO)
    print("  T1 %s T0: distinct=%d %s" % (nm, len(ds), "CONSTANT=%08x" % ds.pop() if len(ds) == 1 else ""))
print("=== 2. T0/T1 inside d4? W0 inside d4? T0==d2? ===")
for nm, f in [("T0 in a", lambda r: r["t"][0] in r["a"]), ("T1 in a", lambda r: r["t"][1] in r["a"]),
              ("W0 in a", lambda r: r["W0"] in r["a"]), ("T0==d2", lambda r: r["t"][0] == r["d2"]),
              ("T1==d2", lambda r: r["t"][1] == r["d2"]), ("W0==d2", lambda r: r["W0"] == r["d2"]),
              ("W0==T0", lambda r: r["W0"] == r["t"][0]), ("W0==T1", lambda r: r["W0"] == r["t"][1])]:
    n = sum(1 for r in INFO if f(r))
    print("  %-8s %d/11%s" % (nm, n, "  <--" if n >= 9 else ""))
print("=== 3. H halves vs R/Xhi/Xlo (6 clean rows) ===")
for i in (0, 1, 4, 5, 6, 7):
    r = INFO[i]
    Hb = r["H"]
    halves = set()
    for j in range(0, 32, 2):
        halves.add(int.from_bytes(Hb[j:j+2], "big"))
        halves.add(int.from_bytes(Hb[j:j+2], "little"))
    Xhi, Xlo = (r["X"] >> 16) & 0xFFFF, r["X"] & 0xFFFF
    print("  [%d] R:%s Xhi:%s Xlo:%s" % (i, r["R"] in halves, Xhi in halves, Xlo in halves))
