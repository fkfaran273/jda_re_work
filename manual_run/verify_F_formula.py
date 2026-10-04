"""verify_F_formula.py — the closed form of the whitening cipher's F map,
and an end-to-end proof that it can replace the stored 32-row table.

THE FORMULA
-----------
F is a linear map on a 32-bit word, treated as 4 bytes.  With
    ROTL1(x) = ((x << 1) | (x >> 7)) & 0xFF      (bit r of the result = bit r-1)
    RESID  = 0x1A                                 (output bits {1,3,4})
and byte indices taken cyclically mod 4:

    for i in 0..3:
        w0,w1,w2,w3 = byte[i], byte[i+1], byte[i+2], byte[i+3]
        out[i] = ROTL1(w0) ^ (RESID if w0 & 0x80 else 0)
               ^ ROTL1(w1) ^ w1          ^ (RESID if w1 & 0x80 else 0)
               ^ w2 ^ w3

That replaces 32 rows x 32 bits (128 bytes) with zero tables and one constant.

WHY IT IS PROVEN, NOT GUESSED
-----------------------------
F and the formula are both linear over GF(2).  Two linear maps that agree on
every single-bit basis vector are identical everywhere.  So the basis test
below is a complete proof; the 2-bit, 3-bit, full-matrix and random sweeps are
belt-and-braces.

The end-to-end check then swaps F_word for the formula inside the live signer
and re-derives the six genuine captures, which exercises whitening, the block,
the digest and the whole record assembly.
"""
import base64
import itertools
import random
import re
import sys

HERE = __import__("os").path.dirname(__import__("os").path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_pure as P
import adj9_decode as D   # noqa: E402
import f_reference as R   # noqa: E402  the extracted matrices

RESID = 0x1A


def rotl1(x):
    return ((x << 1) | (x >> 7)) & 0xFF


def F_formula(x):
    b = [(x >> (8 * i)) & 0xFF for i in range(4)]
    out = 0
    for i in range(4):
        w0, w1, w2, w3 = b[i], b[(i + 1) % 4], b[(i + 2) % 4], b[(i + 3) % 4]
        ob = (rotl1(w0) ^ (RESID if (w0 & 0x80) else 0)
              ^ rotl1(w1) ^ w1 ^ (RESID if (w1 & 0x80) else 0)
              ^ w2 ^ w3)
        out |= ob << (8 * i)
    return out


def main():
    print("=" * 72)
    print("PART 1  the formula reproduces F_word")
    print("=" * 72)
    basis = all(F_formula(1 << i) == R.F_word(1 << i) for i in range(32))
    print("   single-bit basis (a COMPLETE proof, both sides linear):", basis)
    two = all(F_formula((1 << i) | (1 << j)) == R.F_word((1 << i) | (1 << j))
              for i in range(32) for j in range(32))
    three = all(F_formula(sum(1 << i for i in c))
                == R.F_word(sum(1 << i for i in c))
                for c in itertools.combinations(range(32), 3))
    print("   all 496 pairs                                     :", two)
    print("   all 4960 triples                                  :", three)
    xs = [random.getrandbits(32) for _ in range(50000)]
    print("   50000 random words                                 :",
          sum(1 for x in xs if F_formula(x) != R.F_word(x)) == 0)
    reb = []
    for j in range(32):
        v = 0
        for i in range(32):
            if (F_formula(1 << i) >> j) & 1:
                v |= 1 << i
        reb.append(v)
    print("   rebuilt matrix == F_ROWS                           :",
          reb == list(R.F_ROWS))

    print()
    print("=" * 72)
    print("PART 2  end to end: swap F_word for the formula, re-derive the")
    print("        six genuine captures.  Nothing else changes.")
    print("=" * 72)
    # install the formula as the live forward implementation.  Only the
    # forward path is needed for signing; the inverse is left alone.
    orig = P.mix_columns
    P.mix_columns = lambda x: F_formula(x)

    import base64
    import json
    import re
    log = ("..\\adj9\\rev\\win_capture\\module_win_capture.log")
    lines = open(log, encoding="utf-8", errors="replace").read().split("\n")
    si = [i for i, l in enumerate(lines)
          if l.startswith("###ADJ9_BEGIN type=sign_input")]
    ah = [i for i, l in enumerate(lines)
          if l.startswith("###ADJ9_BEGIN type=authorization_header")]
    base = json.load(open("apps.json"))["penti"]
    ok = tot = 0
    for n, (i, j) in enumerate(zip(si, ah)):
        v = {}
        for k in range(i, i + 10):
            if lines[k].startswith("map_order="):
                for p in lines[k][len("map_order="):].split("\x02"):
                    if "\x01" in p:
                        kk, vv = p.split("\x01", 1)
                        v[kk] = vv
                break
        blob = base64.b64decode(
            re.search(r'signature="([A-Za-z0-9+/=]+)"', lines[j + 2]).group(1))
        ts = int(re.search(r"ts=(\d{13})", lines[i]).group(1)) // 1000
        rec = D.whiten_body_inverse(blob[16:160], blob[:16])
        seed = int.from_bytes(rec[20:24], "big")
        phase = None
        for cnt in (1, 2, 3):
            for ph in itertools.permutations(range(0x20, 0x50), cnt):
                try:
                    if P.head16_for(seed, ph) == rec[3:19]:
                        phase = ph
                        break
                except Exception:
                    continue
            if phase:
                break
        kind = v.get("activity_kind", "session")
        best = 0
        camp = dict(base, cert_sha1=rec[25:45].hex())
        P.campaign_data = camp
        for law in (P.claims_padded_58, P.claims_padded):
            sv = P.claims_padded
            P.claims_padded = law
            try:
                auth = P.sign_request(v, kind, head=phase,
                                      second=ts, seed=seed)
                got = base64.b64decode(
                    re.search(r'signature="([^"]+)"', auth).group(1))
                best = max(best, sum(a == b for a, b in zip(got, blob)))
            except Exception:
                pass
            P.claims_padded = sv
        ok += best == 192
        tot += 1
        print("   win%d  %3d/192 %s" % (n, best, "EXACT" if best == 192 else "FAIL"))
    P.mix_columns = orig
    print()
    print("   %d/%d genuine captures reproduced with the FORMULA" % (ok, tot))
    good = basis and two and three and reb == list(R.F_ROWS) and ok == tot
    print()
    print("RESULT:", "F HAS A VERIFIED CLOSED FORM" if good else "FAILED")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())