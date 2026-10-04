"""xhi_probe.py - is W0 (or #2) a 16-bit value BORROWED from another slot?

Finding: d0's tile is tiled2 XOR K02, odd words XOR K13, where K13 = R||R
(R = 16-bit row tag), and rows 0-8 have K02hi == R. #2's high16 has 4 bits
in common with R in 6/10 rows -- worth testing against full words.

Tests on all 11 rows (10 + app):
  1. Is W0's HIGH16 or LOW16 == R? (any row)
  2. Is W0 == (R<<16)|X or (X<<16)|R for X = a word of H/claims/sec?
  3. Is #2's HIGH16 or LOW16 == R?  Is #2's OTHER half == low16 of something?
  4. Is R (as 16-bit or R||R) a substring of H (bytes) or of the blob header?
  5. Does (R || R) appear as a dword in H/beats: full-word membership?
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
M = 0xFFFFFFFF
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
A = json.load(open(os.path.join(HERE, "app_signings.json"), encoding="utf-8"))[0]
PH = {r["i"]: r for r in json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))}


def be(hexs, n=None):
    raw = bytes.fromhex(hexs)
    if n is None:
        n = len(raw) // 4
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 4 * n, 4)]


ROWS = []
for i, x in enumerate(S):
    t = be(x["d0"])[1:5]
    K13 = (t[3] ^ t[1]) & M
    R16 = (K13 >> 16) & 0xFFFF
    RR = ((R16 << 16) | R16) & M
    ROWS.append({"i": i, "R": R16, "RR": RR, "W0": be(x["d0"])[0],
                 "tile": t, "d2": int(x["d2"], 16), "d4": be(x["d4"], 8),
                 "claims": bytes.fromhex(x["d10"]),
                 "H": bytes.fromhex(PH[i]["H"]) if i in PH and PH[i].get("H") else None,
                 "sec": PH[i].get("second") if i in PH else None})
ta = be(A["d0"])[1:5]
K13a = (ta[3] ^ ta[1]) & M
Ra = (K13a >> 16) & 0xFFFF
ROWS.append({"i": "app", "R": Ra, "RR": ((Ra << 16) | Ra) & M, "W0": be(A["d0"])[0],
             "tile": ta, "d2": int(A["d2"], 16), "d4": be(A["d4"], 8),
             "claims": bytes.fromhex(A["d10"]), "H": None, "sec": A["second"]})

print("--- 1. W0 halves vs R ---")
for r in ROWS:
    hi, lo = (r["W0"] >> 16) & 0xFFFF, r["W0"] & 0xFFFF
    print("  [%-3s] W0=%08x R=%04x hi==R:%s lo==R:%s" %
          (r["i"], r["W0"], r["R"], hi == r["R"], lo == r["R"]))

print()
print("--- 2. #2 halves vs R ---")
for r in ROWS:
    hi, lo = (r["d2"] >> 16) & 0xFFFF, r["d2"] & 0xFFFF
    print("  [%-3s] #2=%08x R=%04x hibit=%d lobit=%d" %
          (r["i"], r["d2"], r["R"],
           sum(1 for b in range(16) if ((hi >> b) & 1) == ((r["R"] >> b) & 1)),
           sum(1 for b in range(16) if ((lo >> b) & 1) == ((r["R"] >> b) & 1))))

print()
print("--- 3. R||R as dword inside H / claims / blob / header? ---")
for r in ROWS:
    if r["i"] == "app":
        continue
    hits = []
    rr_be = r["RR"].to_bytes(4, "big")
    rr_le = r["RR"].to_bytes(4, "little")
    if r["H"] and (rr_be in r["H"] or rr_le in r["H"]):
        hits.append("H")
    if rr_be in r["claims"] or rr_le in r["claims"]:
        hits.append("claims")
    if r["i"] in PH and PH[r["i"]].get("blob"):
        bb = bytes.fromhex(PH[r["i"]]["blob"])
        if rr_be in bb or rr_le in bb:
            hits.append("blob")
    rh = r["R"].to_bytes(2, "big")
    h16 = []
    if r["H"] and rh in r["H"]:
        h16.append("H")
    if rh in r["claims"]:
        h16.append("claims")
    print("  [%d] R=%04x RR=%08x RR-in=%s R16-in=%s" %
          (r["i"], r["R"], r["RR"], hits or "none", h16 or "none"))

print()
print("--- 4. tile[i] halves vs R (where is the tag NOT?) ---")
for r in ROWS:
    line = []
    for k, t in enumerate(r["tile"]):
        hi, lo = (t >> 16) & 0xFFFF, t & 0xFFFF
        line.append("t%d:hi==R:%s,lo==R:%s" % (k, hi == r["R"], lo == r["R"]))
    print("  [%-3s] R=%04x %s" % (r["i"], r["R"], " ".join(line)))

print()
print("--- 5. R vs #4 words (full-word) / second low16 / H low16s ---")
for r in ROWS:
    in4 = [k for k, a in enumerate(r["d4"]) if ((a >> 16) & 0xFFFF) == r["R"] or (a & 0xFFFF) == r["R"]]
    s16 = (r["sec"] & 0xFFFF) if r["sec"] else None
    print("  [%-3s] R=%04x in-#4halves@%s sec-lo16=%s eq=%s" %
          (r["i"], r["R"], in4 or "none", "%04x" % s16 if s16 is not None else "-",
           s16 == r["R"] if s16 is not None else "-"))
