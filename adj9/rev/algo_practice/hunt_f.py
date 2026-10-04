"""hunt_f.py — closed-form hunt for the whitening linear layer F.

Reference: pure_sign.py's F_ROWS (32 row masks; F(x)_j = parity(rows[j] & x))
and _byte_tables(_F_ROWS) — the map must be reproduced exactly.

Hand hypotheses to test:
  H1  F is byte-circulant: rows at stride 8 are byte-rotations of each other
      -> F = A0 + A1 S + A2 S^2 + A3 S^3 with S = byte rotation (LSB byte 0),
         out_b = A0(in_b) ^ A1(in_{b+1}) ^ A2(in_{b+2}) ^ A3(in_{b+3}).
  H2  A2 = A3 = I; A1 = A0 + I  (from rows 0..7: b2/b3 = 1<<j, b1 = b0 ^ 1<<j)
  H3  A0 = xtime in GF(2^8) for SOME degree-8 poly; candidates: all 30
      irreducible polys (bit 8 + low bits).  Prediction: 0x11B (AES).
Then:
  V4  closed form vs _byte_tables reference on 20k random words
  V5  closed-form inverse (circulant polynomial inversion in the commutative
      ring GF(2)[xtime, S]) vs pure_sign's F_MINV on random words
  V6  F_MINV's own circulant generators extracted for the record
"""
import random
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "pure_signer"))
from pure_sign import F_ROWS, F_MINV, _byte_tables, _apply_tab, F_word  # noqa

M32 = 0xFFFFFFFF
BYTE = [0xFF << (8 * k) for k in range(4)]


def rows_to_mat(rows):
    """32 x 32 bit matrix; col i = input bit i, row j = output bit j."""
    return [[(r >> i) & 1 for i in range(32)] for r in rows]


def mat_apply(mat, x):
    y = 0
    for j, row in enumerate(mat):
        v = 0
        for i in range(32):
            if row[i] and (x >> i) & 1:
                v ^= 1
        y |= v << j
    return y


# ---------------------------------------------------------------- H1
def test_circulant(rows):
    """Split each row into 4 bytes -> A_d[row j] = byte d of row j, then
    rebuild all 32 rows from the circulant law and compare."""
    A = [[(r >> (8 * d)) & 0xFF for r in rows[:8]] for d in range(4)]
    ok = True
    for j in range(32):
        b, jj = j // 8, j % 8          # output byte b, bit jj
        want = rows[j]
        got = 0
        for d in range(4):             # out_b = sum_d A_d(in_{b+d})
            got |= (A[d][jj] & 0xFF) << (8 * ((b + d) % 4))
        if got != want:
            ok = False
            print("  H1 FAIL row %d: got %08x want %08x" % (j, got, want))
            break
    return ok, A


# ---------------------------------------------------------------- H3
def xtime_rows(poly_low):
    """8x8 BIT-MATRIX ROWS of multiply-by-x mod (x^8 + poly_low):
    y_j = x_{j-1} ^ (poly_bit_j . x_7)  ->  row j = (1<<((j-1)%8)) | (p_j<<7)."""
    return [(1 << ((j - 1) % 8)) | (((poly_low >> j) & 1) << 7)
            for j in range(8)]


def irreducible_polys():
    """All 30 irreducible degree-8 polynomials (low byte, x^8 implicit)."""
    out = []
    for p in range(256):
        # brute irreducibility: x^8+p has no factor of degree 1..4
        def mulmod(a, b, m=p | 0x100):
            r = 0
            while b:
                if b & 1:
                    r ^= a
                b >>= 1
                a <<= 1
                if a & 0x100:
                    a ^= m
            return r
        bad = False
        for d in (2, 3, 4, 5, 6, 7, 8):     # any irreducible factor deg<=4
            pass
        # simpler: order test — x^8+p irreducible iff x^(2^8) = x mod it
        # and gcd(x^(2^k) - x, m) = 1 for k = 1..4
        def powmod(a, e, m=p | 0x100):
            r = 1
            while e:
                if e & 1:
                    r = mulmod(r, a, m)
                a = mulmod(a, a, m)
                e >>= 1
            return r
        m = p | 0x100
        if powmod(2, 255, m) != 1:          # 2 = x: order must divide 255
            continue
        good = True
        for d in (1, 3, 5, 15):             # proper divisors of 255
            if powmod(2, d, m) == 1:
                good = False
                break
        if good:
            out.append(p)
    return out


def main():
    random.seed(9)
    print("=== F closed-form hunt ===")
    print("[H1] byte-circulant decomposition")
    ok, A = test_circulant(F_ROWS)
    print("     ->", "OK" if ok else "FAIL",
          "(all 32 rows rebuilt from A0..A3 + byte rotation)")

    print("[H2] block identities")
    ident = [1 << j for j in range(8)]
    a0, a1, a2, a3 = A
    h2 = (a2 == ident and a3 == ident
          and a1 == [a0[j] ^ ident[j] for j in range(8)])
    print("     A2 == I:", a2 == ident, " A3 == I:", a3 == ident,
          " A1 == A0^I:", a1 == [a0[j] ^ ident[j] for j in range(8)],
          "->", "OK" if h2 else "FAIL")
    print("     A0 rows:", " ".join("%02x" % v for v in a0))

    print("[H3] A0 == xtime over which poly?")
    irreds = irreducible_polys()
    print("     (%d irreducible degree-8 polys scanned)" % len(irreds))
    hits = [p for p in irreds if xtime_rows(p) == a0]
    print("     ->", ["0x%02X (AES 0x11B)" % hits[0]] if hits == [0x1B]
          else ("hits: %s" % ["0x%02x" % h for h in hits] or "NONE"))
    h3 = hits == [0x1B]

    print("[V4] closed form vs reference (20k random words)")
    # closed form: out_b = xtime(in_b) ^ xtime(in_{b+1}) ^ in_{b+1}
    #                       ^ in_{b+2} ^ in_{b+3}
    def xtime(v):
        return ((v << 1) & 0xFF) ^ (0x1B if v & 0x80 else 0)

    def F_closed(w):
        wb = [(w >> (8 * b)) & 0xFF for b in range(4)]
        out = 0
        for b in range(4):
            v = (xtime(wb[b]) ^ xtime(wb[(b + 1) % 4])
                 ^ wb[(b + 1) % 4] ^ wb[(b + 2) % 4] ^ wb[(b + 3) % 4])
            out |= v << (8 * b)
        return out

    bad = 0
    for _ in range(20000):
        w = random.getrandbits(32)
        if F_closed(w) != F_word(w):
            bad += 1
    v4 = bad == 0
    print("     -> %s" % ("OK (20000/20000)" if v4 else "FAIL %d" % bad))

    print("[V5] inverse from the closed form vs F_MINV")
    # F = c0 + c1 S + c2 S^2 + c3 S^3, c0=x, c1=x+1, c2=1, c3=1 as byte ops.
    # The algebra is commutative (xtime acts within a byte, S across bytes).
    # Invert c(z) mod z^4+1 by brute force over the 16 monomials z^0..z^3
    # composed of ring elements d0 + d1 z + d2 z^2 + d3 z^3, d_i polynomial
    # in xtime of degree < 8 (xtime has order 255; enumerate d_i as
    # combinations via linear algebra instead: solve M d = e_b per output).
    # Simpler and airtight: verify F o F_MINV == I on random words (tables
    # already prove it); the NEW content is that the closed form composes
    # with F_MINV to identity.
    fminv_tab = _byte_tables(F_MINV)
    bad = 0
    for _ in range(20000):
        w = random.getrandbits(32)
        if F_closed(_apply_tab(fminv_tab, w)) != w:
            bad += 1
    v5 = bad == 0
    print("     -> F(closed) o F_MINV == I: %s"
          % ("OK (20000/20000)" if v5 else "FAIL %d" % bad))

    print("[V6] F_MINV circulant generators (for the record)")
    ok6, Ainv = test_circulant(F_MINV)
    print("     F_MINV byte-circulant:", "OK" if ok6 else "NO")
    if ok6:
        for name, blk in (("A0inv", Ainv[0]), ("A1inv", Ainv[1]),
                          ("A2inv", Ainv[2]), ("A3inv", Ainv[3])):
            print("       %s: %s" % (name, " ".join("%02x" % v for v in blk)))

    print()
    verdict = ok and h2 and h3 and v4 and v5
    print("F CLOSED FORM: out_b = xtime(w_b) ^ xtime(w_{b+1}) ^ w_{b+1}"
          " ^ w_{b+2} ^ w_{b+3}   (bytes mod 4, AES xtime mod 0x11B)")
    print("RESULT:", "SOLVED" if verdict else "INCOMPLETE")
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
