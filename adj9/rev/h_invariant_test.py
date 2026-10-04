"""h_invariant_test.py - is the envelope provably independent of H?

The region law says:   d2 = LE-store(seed) read BE,  d4 = f(seed), d0 = g(d4)
with seed = V ^ (pid<<16).  d2 is 4 bytes and fully determines seed, so if d4
and d0 are recoverable from d2 alone, the 32-byte descriptor #4 carries no
information that H could be supplying.

We reconstruct the seed from each row's d2, regenerate d4/d0 through F.py, and
compare against the captured values. A full match means the 176-byte body is a
pure function of (signing second, claims, cert) -- H contributes nothing, and
the "server checks H" theory cannot explain the Organic/Python result.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import F

A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
P3 = json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))
AUD = {r["i"]: r for r in
       json.load(open(os.path.join(HERE, "audit_pairs_result.json"), encoding="utf-8"))}

# rows whose blob is verifiably their own (audit says so)
GOOD = [r for r in P3 if AUD.get(r["i"], {}).get("verdict") == "exact"]
print("self-consistent rows: %s\n" % [r["i"] for r in GOOD])


def words(hexstr):
    raw = bytes.fromhex(hexstr)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, len(raw), 4)]


ok_d4 = ok_d0 = 0
for r in GOOD:
    i = r["i"]
    a = A[i]
    d2 = int(a["d2"], 16)
    # d2 is the little-endian store of seed read back big-endian
    seed = int.from_bytes(d2.to_bytes(4, "big"), "little")

    d4_want = words(a["d4"])
    d0_want = words(a["d0"])
    d4_got = F._d4_words(seed)
    d0_got = F._d0_words(d4_got)

    m4 = d4_got == d4_want
    m0 = d0_got == d0_want
    ok_d4 += m4
    ok_d0 += m0
    print("[%2d] seed=%08x  d4 %-5s  d0 %-5s  H=%s..." %
          (i, seed, "MATCH" if m4 else "diff", "MATCH" if m0 else "diff",
           (r["H"] or "none")[:16]))
    if not m4:
        print("      d4 got  %s" % [f"{x:08x}" for x in d4_got[:6]])
        print("      d4 want %s" % [f"{x:08x}" for x in d4_want[:6]])
    if not m0:
        bad = [k for k in range(len(d0_want)) if d0_got[k] != d0_want[k]]
        print("      d0 differs at %d/%d words, first idx %s" %
              (len(bad), len(d0_want), bad[:8]))

print()
print("d4 recoverable from d2 alone: %d/%d" % (ok_d4, len(GOOD)))
print("d0 recoverable from d2 alone: %d/%d" % (ok_d0, len(GOOD)))
print()
if ok_d4 == len(GOOD) and ok_d0 == len(GOOD):
    print("VERDICT: the region is a pure function of the 4-byte d2.")
    print("H carries no information into the body. The envelope is")
    print("H-independent, so H cannot be the server's organic/non-organic gate.")
