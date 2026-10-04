"""constx_probe.py - is the region (public constant) XOR (per-signing random)?

Model: region_value[i] = CONST[i] XOR K_row[i], where K_row is per-signing
keystream.  Under this model region[i]^region[j] (same slot, rows i,j) =
K_i ^ K_j -- i.e. pairwise XORs REMOVE the constant and expose the keystream.
Test: do K-differences show shared structure the raw region values do not?
 1. K02_high16 across the 11 rows (tile structure probe found row-constant 16-bit halves).
 2. region pairwise-xor bit-length distribution: per-slot, are some slots
    systematically shorter (CONST-heavy) vs full-width (keystream-heavy)?
 3. claims_len vs region: does #2 or W0 equal claims_len XOR K for constant K?
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
M = 0xFFFFFFFF
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
A = json.load(open(os.path.join(HERE, "app_signings.json"), encoding="utf-8"))[0]
ROWS = [(i, x["d0"], x["d2"], x["d4"], len(bytes.fromhex(x["d10"]))) for i, x in enumerate(S)]
ROWS.append(("app", A["d0"], A["d2"], A["d4"], len(bytes.fromhex(A["d10"]))))


def be(hexs, n=None):
    raw = bytes.fromhex(hexs)
    if n is None:
        n = len(raw) // 4
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 4 * n, 4)]


D = []
for i, d0, d2, d4, cl in ROWS:
    w = be(d0)
    W0, tile = w[0], be(d0)[1:5]
    D.append({"i": i, "W0": W0, "tile": tile, "d2": int(d2, 16),
              "d4": be(d4, 8), "cl": cl})

print("--- 1. K02 halves across 11 rows ---")
for r in D:
    k = (r["tile"][2] ^ r["tile"][0]) & M
    l = (r["tile"][3] ^ r["tile"][1]) & M
    kh, kl = (k >> 16) & 0xFFFF, k & 0xFFFF
    lh, ll = (l >> 16) & 0xFFFF, l & 0xFFFF
    print("  [%-3s] K02=%08x hi=%04x lo=%04x  K13=%08x hi=%04x lo=%04x same-lo=%s" %
          (r["i"], k, kh, kl, l, lh, ll, kl == ll))

print()
print("--- 2. pairwise-XOR bit-lengths per slot (CONST-heavy = short) ---")
slots = ["W0", "tile0", "tile1", "tile2", "tile3", "#2"] + ["#4[%d]" % k for k in range(8)]


def val(r, s):
    if s == "W0":
        return r["W0"]
    if s.startswith("tile"):
        return r["tile"][int(s[4])]
    if s == "#2":
        return r["d2"]
    return r["d4"][int(s[3])]


for s in slots:
    vs = [val(r, s) for r in D]
    xors = [(vs[i] ^ vs[j]) & M for i in range(len(vs)) for j in range(i + 1, len(vs))]
    mx, mn = max(x.bit_length() for x in xors), min(x.bit_length() for x in xors)
    avg = sum(x.bit_length() for x in xors) / len(xors)
    print("  %-6s maxbits=%-2d minbits=%-2d avg=%5.1f" % (s, mx, mn, avg))

print()
print("--- 3. claims_len XOR region (constant K?) ---")
for nm, f in (("W0", lambda r: r["W0"]), ("#2", lambda r: r["d2"]),
              ("tile0", lambda r: r["tile"][0]), ("#4[0]", lambda r: r["d4"][0])):
    ks = set((f(r) ^ r["cl"]) & M for r in D)
    print("  %-6s distinct K=%d" % (nm, len(ks)))
