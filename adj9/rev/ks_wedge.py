"""ks_wedge.py — THE 7/9 keystream-cancellation probe.

Rows 7 and 9 of all_signings carry BYTE-IDENTICAL 360-B claims (slice 127 §6),
so the builder plaintext P is identical for both. Under the determinism result
(slice 116: body = f(map, second)), the region difference is then PURE
KEYSTREAM DIFFERENCE:

    region7 ^ region9 = ks(S7) ^ ks(S9)      per slot

If the keystream is derived from Random3(second) (the same generator the header
uses, consuming draws after/beside the header's 8), we can brute-force S9 and
require ONE candidate second to satisfy every slot simultaneously.

Success: one S9 matches W0+tile+##2+##4 with a single extraction rule
=> keystream is second-derived => region is computable => pure-Python signer.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import Random3

M = 0xFFFFFFFF
S = json.load(open(os.path.join(HERE, "all_signings.json")))
P = json.load(open(os.path.join(HERE, "pair_h3.json")))
SEC = {r["i"]: r["second"] for r in P}
H = {r["i"]: r["H"] for r in P}

def words(hexstr):
    b = bytes.fromhex(hexstr)
    return list(struct.unpack(">%dI" % (len(b) // 4), b))

def region(row):
    d0 = bytes.fromhex(row["d0"])
    w0 = words(row["d0"][:8])[0]
    tile = words(row["d0"][8:40])            # first 16-B tile = 4 words
    d4 = words(row["d4"])
    d2 = words(row["d2"])[0]
    return {"W0": w0, "tile": tile, "d4": d4, "d2": d2}

r7, r9 = S[7], S[9]
print("claims identical:", r7["d10"] == r9["d10"])
print("H7 == H9:", H.get(7), H.get(9),
      "same" if H.get(7) == H.get(9) else "differ/unknown")

R7, R9 = region(r7), region(r9)
S7 = SEC[7]
print("S7 =", S7)

# D per slot (same-length slots only)
D = {"W0": R7["W0"] ^ R9["W0"], "d2": R7["d2"] ^ R9["d2"]}
D["tile"] = [a ^ b for a, b in zip(R7["tile"], R9["tile"])]
D["d4"] = [a ^ b for a, b in zip(R7["d4"], R9["d4"])]
print("D W0 = %08x  D d2 = %08x" % (D["W0"], D["d2"]))
print("D tile =", " ".join("%08x" % x for x in D["tile"]))
print("D d4   =", " ".join("%08x" % x for x in D["d4"]))


def ks_words(sec, form, off, n):
    """keystream candidate: n words from Random3(sec)."""
    r = Random3(sec)
    draws = [r.next() & M for _ in range(off + 2 * n + 2)]
    if form == "raw":                        # raw draws
        return draws[off:off + n]
    if form == "pair":                       # header-style xor pairs
        return [draws[off + 2 * i] ^ draws[off + 2 * i + 1]
                for i in range(n)]
    if form == "rawLE":
        return [int.from_bytes(x.to_bytes(4, "little"), "big")
                for x in draws[off:off + n]]
    raise ValueError(form)


FORMS = [("raw", 0), ("raw", 8), ("pair", 0), ("pair", 8),
         ("raw", 16), ("pair", 16), ("raw", 32), ("pair", 32),
         ("raw", 64), ("pair", 64), ("rawLE", 0), ("rawLE", 8)]

# brute-force S9 in a window around S7
LO, HI = S7 - 7200, S7 + 7200
hits = []
for form, off in FORMS:
    k7 = ks_words(S7, form, off, 14)         # 1 W0 + 4 tile + 8 d4 + 1 d2
    for s9 in range(LO, HI + 1):
        k9 = ks_words(s9, form, off, 14)
        ok = True
        # W0 (idx 0), tile (1..4), d4 (5..12), d2 (13)
        for idx, dv in [(0, D["W0"]), (13, D["d2"])]:
            if (k7[idx] ^ k9[idx]) != dv:
                ok = False
                break
        if ok:
            for j in range(4):
                if (k7[1 + j] ^ k9[1 + j]) != D["tile"][j]:
                    ok = False
                    break
        if ok:
            for j in range(8):
                if (k7[5 + j] ^ k9[5 + j]) != D["d4"][j]:
                    ok = False
                    break
        if ok:
            hits.append((form, off, s9))
            print("HIT form=%s off=%d S9=%d" % (form, off, s9), flush=True)
    if len(hits) > 4:
        break

print()
if hits:
    print("SUCCESS: keystream is second-derived.", hits[:5])
else:
    print("no Random3-derived keystream matches in [%d, %d] x %d forms"
          % (LO, HI, len(FORMS)))
    print("=> keystream is NOT Random3(second); next: H-derived or builder-"
          "internal (Path B).")
