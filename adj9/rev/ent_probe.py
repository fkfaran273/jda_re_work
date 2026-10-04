"""ent_probe.py - per-word entropy: which region words are random vs structured?

For each of the 14 region words (W0, T0..T3, d2, a0..a7) over all 11 rows:
  * distinct count (11 = fully random-looking)
  * bit-length of pairwise XORs (structured = short)
  * popcount mean (random u32 ~ 16; sparse bitfield << 16)
  * byte0 alphabet size (HMAC-uniform = ~11 distinct; structured = small)
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
            return w[0], t
    return w[0], w[1:5]
WORDS = {}
for i, x in enumerate(S):
    W0, t = canon(x)
    a = [int.from_bytes(bytes.fromhex(x["d4"])[j:j+4], "big") for j in range(0, 32, 4)]
    vals = {"W0": W0, "T0": t[0], "T1": t[1], "T2": t[2], "T3": t[3],
            "d2": int(x["d2"], 16)}
    for k in range(8):
        vals["a%d" % k] = a[k]
    for nm, v in vals.items():
        WORDS.setdefault(nm, []).append(v)
W0a, ta = canon({"d0": A["d0"]})
aa = [int.from_bytes(bytes.fromhex(A["d4"])[j:j+4], "big") for j in range(0, 32, 4)]
WORDS["W0"].append(W0a)
for k, v in enumerate(ta):
    WORDS["T%d" % k].append(v)
WORDS["d2"].append(int(A["d2"], 16))
for k in range(8):
    WORDS["a%d" % k].append(aa[k])
print("%-4s distinct popmean  xoravg  b0alpha" % "slot")
for nm in ["W0", "T0", "T1", "T2", "T3", "d2"] + ["a%d" % k for k in range(8)]:
    vs = WORDS[nm]
    d = len(set(vs))
    pop = sum(bin(v).count("1") for v in vs) / len(vs)
    xors = [(vs[i] ^ vs[j]) & M for i in range(len(vs)) for j in range(i + 1, len(vs))]
    xav = sum(x.bit_length() for x in xors) / len(xors)
    b0 = len(set((v >> 24) & 0xFF for v in vs))
    print("%-4s %-8d %-7.1f  %-6.1f  %-7d" % (nm, d, pop, xav, b0))
