"""test_f_formula.py — asserts the generating formula for F_ROWS and F_MINV.

Found formula (verified 32/32 rows for both tables):

    F is exactly AES MixColumns with the standard circulant matrix
    [2, 3, 1, 1] over GF(2^8) modulo 0x11B, applied to the four bytes of a
    32-bit word (byte 0 = least significant byte):

        y_b = 2*x_b  ^  3*x_(b+1)  ^  x_(b+2)  ^  x_(b+3)     (indices mod 4)

    F_MINV is the corresponding inverse circulant [14, 11, 13, 9]
    (AES InvMixColumns):

        x_b = 14*y_b  ^  11*y_(b+1)  ^  13*y_(b+2)  ^  9*y_(b+3)

Description size: 4 byte coefficients per table (8 bits each) + the AES
polynomial 0x11B, versus 1024 bits per stored table (256 bits each after the
byte-cyclic compression M[j+8] == rot32(M[j], 8)).

Equivalent branch-free word form (one xtime per call, SWAR over 4 bytes):

    xt(x) = ((x << 1) & 0xFEFEFEFE) ^ (((x & 0x80808080) >> 7) * 0x1B)
    F(x)  = xt(x ^ rotr32(x, 8)) ^ rotr32(x, 8) ^ rotr32(x, 16) ^ rotr32(x, 24)

Run standalone:  python test_f_formula.py
Or under pytest: pytest test_f_formula.py
"""
import random
import sys

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\manual_run")
import adj9_pure as P
import f_reference as R

MASK32 = 0xFFFFFFFF
AES_POLY = 0x11B          # x^8 + x^4 + x^3 + x + 1
FWD_COEFFS = [2, 3, 1, 1]         # MixColumns, circulant, first row
INV_COEFFS = [14, 11, 13, 9]      # InvMixColumns, circulant, first row


def gmul(a, b):
    """multiplication in GF(2^8) modulo 0x11B"""
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= AES_POLY
    return r & 0xFF


def xt_word(x):
    """bytewise AES xtime on a 32-bit word (SWAR, no per-byte loops)"""
    m = x & 0x80808080
    return (((x << 1) & 0xFEFEFEFE) ^ (((m >> 7) * 0x1B) & MASK32)) & MASK32


def rotr32(v, k):
    return ((v >> k) | (v << (32 - k))) & MASK32


def F_swar(x):
    """F as one line of word arithmetic (equivalent to the circulant form)"""
    z = rotr32(x, 8)
    return xt_word(x ^ z) ^ z ^ rotr32(x, 16) ^ rotr32(x, 24)


def F_circulant(x):
    """F in the explicit MixColumns form, byte indices cyclic mod 4"""
    b = [(x >> (8 * i)) & 0xFF for i in range(4)]
    y = 0
    for i in range(4):
        v = 0
        for p, c in enumerate(FWD_COEFFS):
            v ^= gmul(c, b[(i + p) % 4])
        y |= v << (8 * i)
    return y & MASK32


def F_inv_circulant(y):
    """F inverse in the explicit InvMixColumns form"""
    b = [(y >> (8 * i)) & 0xFF for i in range(4)]
    x = 0
    for i in range(4):
        v = 0
        for p, c in enumerate(INV_COEFFS):
            v ^= gmul(c, b[(i + p) % 4])
        x |= v << (8 * i)
    return x & MASK32


def circulant_rows(coeffs):
    """32x32 GF(2) matrix of the circulant byte map, row by row, from e_i images"""
    cols = []
    for i in range(32):
        qb, t = i // 8, i % 8          # input byte qb, input bit t
        y = 0
        for p, c in enumerate(coeffs):
            v = gmul(c, 1 << t)        # image of input bit t through coeff c
            if v:
                y ^= v << (8 * ((qb - p) % 4))
        cols.append(y)
    rows = []
    for j in range(32):
        v = 0
        for i in range(32):
            if (cols[i] >> j) & 1:
                v |= 1 << i
        rows.append(v)
    return rows


def _report(name, ok, detail=""):
    print("  %-58s %s %s" % (name, "PASS" if ok else "FAIL", detail))
    return ok


def run_all():
    all_ok = True

    print("test_f_formula.py — generating formula for F_ROWS / F_MINV")

    fwd_rows = circulant_rows(FWD_COEFFS)
    n = sum(fwd_rows[j] == R.F_ROWS[j] for j in range(32))
    all_ok &= _report("F_ROWS rebuilt from circulant [2,3,1,1]",
                      fwd_rows == list(R.F_ROWS), "(%d/32 rows)" % n)

    inv_rows = circulant_rows(INV_COEFFS)
    n = sum(inv_rows[j] == R.F_MINV[j] for j in range(32))
    all_ok &= _report("F_MINV rebuilt from circulant [14,11,13,9]",
                      inv_rows == list(R.F_MINV), "(%d/32 rows)" % n)

    all_ok &= _report("F_swar  == F_word on all 32 basis vectors",
                      all(F_swar(1 << i) == R.F_word(1 << i) for i in range(32)))
    all_ok &= _report("F_circ  == F_word on all 32 basis vectors",
                      all(F_circulant(1 << i) == R.F_word(1 << i) for i in range(32)))

    rng = random.Random(0xF00D)
    bad_swar = bad_circ = bad_inv = 0
    for _ in range(100000):
        x = rng.getrandbits(32)
        if F_swar(x) != R.F_word(x):
            bad_swar += 1
        if F_circulant(x) != R.F_word(x):
            bad_circ += 1
        if F_inv_circulant(R.F_word(x)) != x:
            bad_inv += 1
    all_ok &= _report("F_swar  == F_word, 100000 random words", bad_swar == 0,
                     "(%d mismatches)" % bad_swar)
    all_ok &= _report("F_circ  == F_word, 100000 random words", bad_circ == 0,
                     "(%d mismatches)" % bad_circ)
    all_ok &= _report("F_inv_circulant o F_word == identity, 100000 words",
                     bad_inv == 0, "(%d failures)" % bad_inv)

    fixed = [0, 1, 0xFFFFFFFF, 0x00000080, 0x80000000, 0x80808080,
             0xDEADBEEF, 0x12345678, 0xA5A5A5A5, 0x01010101]
    all_ok &= _report("formula agrees with F_word on fixed edge cases",
                      all(F_swar(x) == R.F_word(x) == F_circulant(x) for x in fixed))
    all_ok &= _report("inv_mix_columns_doc(F_swar(x)) == x on fixed edge cases",
                      all(R.inv_mix_columns_doc(F_swar(x)) == x for x in fixed))

    print("RESULT:", "ALL PASS" if all_ok else "FAILURES PRESENT")
    return all_ok


def test_f_rows_exact():
    assert circulant_rows(FWD_COEFFS) == list(R.F_ROWS)


def test_f_minv_exact():
    assert circulant_rows(INV_COEFFS) == list(R.F_MINV)


def test_word_level_form():
    for i in range(32):
        assert F_swar(1 << i) == R.F_word(1 << i)
    rng = random.Random(0xF00D)
    for _ in range(10000):
        x = rng.getrandbits(32)
        assert F_swar(x) == R.F_word(x)


if __name__ == "__main__":
    sys.exit(0 if run_all() else 1)
