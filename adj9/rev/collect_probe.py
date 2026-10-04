"""collect_probe.py - WHERE does the region come from? (builder-input hunt)

The builder writes each 16-byte block as `4 words XOR ONE key register`.
The region input words therefore pass through registers on the way in.
Untried sources to test against every region word (11 rows, canon tiles):
  1. R (16-bit tag) zero/sign-extended, R||R, byteswapped variants
  2. nsign_ts / second words (rows with pairing; app row uses second)
  3. claims_len (#7), claims words (head/tail dwords)
  4. H words are TESTED in const_diff2 (0 hits) -- but H BYTES as 16-bit
     halves were never tested against R (R is 16-bit!): is R a half of H?
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
            return w[0], t, R
    return w[0], w[1:5], None
print("=== 4. R as 16-bit half of H? (6 clean rows) ===")
for i in (0, 1, 4, 5, 6, 7):
    W0, t, R = canon(S[i])
    Hb = bytes.fromhex(PH[i]["H"])
    halves = [int.from_bytes(Hb[j:j+2], "big") for j in range(0, 32, 2)]
    halves += [int.from_bytes(Hb[j:j+2], "little") for j in range(0, 32, 2)]
    print("  [%d] R=%04x in-H-halves:%s" % (i, R, R in halves))
print()
print("=== 1+2+3. region words vs small-int sources ===")
for i, x in enumerate(S):
    W0, t, R = canon(x)
    cl = len(bytes.fromhex(x["d10"]))
    sec = PH[i]["second"] if i in PH else None
    ts = PH[i]["nsign_ts"] if i in PH else None
    cands = {"R": R, "RR": ((R << 16) | R) & M, "cl": cl,
             "sec": sec & M if sec else 0, "tslo": (ts & M) if ts else 0}
    row = [W0] + list(t) + [int(x["d2"], 16)]
    hits = []
    for v in row:
        for nm, c in cands.items():
            if v == c or v == (c ^ M) or v == ((c + 1) & M) or v == ((c - 1) & M):
                hits.append("%08x~%s" % (v, nm))
    print("  [%d] %s" % (i, hits or "none"))
