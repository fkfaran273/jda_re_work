"""spn_fit.py — fit GF(2^8) column-mix matrices on chunk-0 round data.

For op X with samples (in16, out16): per column c, per output byte i:
    out[4r+c] = XOR_j M[i][j] (*) in[4j+c]      (column view)
or per row:
    out[4r+c] = XOR_j M[i][j] (*) in[4r+j]      (row view)
Solve M over GF(2) (each of the 16 coefficients = 8 unknown bits) using
GF(2)-linearity of (*) with a fixed multiplier.  Try all 30 polynomials.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))

POLYS = [0x11b, 0x11d, 0x12b, 0x12d, 0x139, 0x13f, 0x14d, 0x15f, 0x163,
         0x165, 0x169, 0x171, 0x177, 0x17b, 0x187, 0x18b, 0x18d, 0x19f,
         0x1a3, 0x1a9, 0x1b1, 0x1bd, 0x1c3, 0x1cf, 0x1d7, 0x1dd, 0x1e7,
         0x1f3, 0x1f5, 0x1f9]


def gmul(a, b, poly):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xFF) ^ (poly if hi else 0)
        b >>= 1
    return p


def load_rounds():
    stores = []
    for line in open(os.path.join(HERE, "spn_footprint.txt")):
        f = line.split()
        if len(f) < 5 or f[1] != "W":
            continue
        stores.append((int(f[0]), int(f[3].split("=")[1], 16),
                       int(f[4].split("=")[1], 16)))
    CELLS = list(range(0x900F09C, 0x900F0DC, 4))
    hist = sorted((wc, a, v) for wc, a, v in stores
                  if a in set(CELLS) and 6100000 <= wc <= 6640000)
    ops = [(int(a) + 5300000, int(b, 16)) for a, b in
           (l.split() for l in open(os.path.join(HERE, "v9_ops.txt")))]
    c0 = ops[1022:1290]
    cur = {}
    si = 0
    snap = []
    for i in range(len(c0) - 1):
        w0, o0 = c0[i]
        w1 = c0[i + 1][0]
        while si < len(hist) and hist[si][0] < w1:
            cur[hist[si][1]] = hist[si][2]
            si += 1
        snap.append((o0, bytes(cur.get(a, 0) for a in CELLS)))
    R = []
    for o, sv in snap:
        if o == 0x1161:
            R.append({"init": sv})
            r = R[-1]
        elif o == 0x1168:
            r = {"sr_in": sv}
            R.append(r)
        elif o == 0x116D:
            r["post_sr"] = sv
        elif o in (0x1312, 0x1341, 0x1372, 0x13A5):
            r.setdefault("quad", []).append((o, sv))
        elif o == 0x1172:
            r["m1"] = sv
        elif o == 0x1177:
            r["m2"] = sv
        elif o == 0x117E:
            R.append({"sr_in": sv, "tail": True})
            r = R[-1]
        elif o == 0x1183:
            r["m1"] = sv
        elif o == 0x1188:
            r["end"] = sv
    return R


def solve_lin(eqs, nvars):
    """eqs: list of (coeff_bits_int (nvars bits), rhs_bit). returns dict or None"""
    rows = [(c, r) for c, r in eqs]
    pivots = {}
    for c, r in rows:
        for b in range(nvars):
            if not (c >> (nvars - 1 - b)) & 1:
                continue
            if b in pivots:
                pc, pr = pivots[b]
                c ^= pc
                r ^= pr
            else:
                pivots[b] = (c, r)
                break
        else:
            if r:
                return None  # inconsistent
    # back-substitute: reduced echelon
    order = sorted(pivots.items(), key=lambda kv: -kv[0])
    sol = [0] * nvars
    for b, (c, r) in order:
        # c has leading bit b; eliminate other bits using solved values
        v = r
        for bb in range(b + 1, nvars):
            if (c >> (nvars - 1 - bb)) & 1:
                v ^= sol[bb]
        sol[b] = v
    # verify
    for c, r in rows:
        v = 0
        for b in range(nvars):
            if (c >> (nvars - 1 - b)) & 1:
                v ^= sol[b]
        if v != r:
            return None
    return sol


def fit(samples, mode, poly):
    """samples: list of (in16, out16). mode 'col' or 'row'.
    Returns M as 4x4 bytes or None."""
    # unknowns: for each (i, j): 8 bits -> variable index (i*4+j)*8 + bit
    nv = 16 * 8
    # The bit-level contribution of coefficient m to m(*)x is NOT linear in
    # the bits of m in general GF mult (it IS: m(*)x = sum_b m_b * (xtime^b(x))
    # and each term is a constant vector). So out_bit_k = XOR_{j,b} m_{ij,b} *
    # (xt^b(x))_k. Build eqs accordingly.
    def xt(v, n):
        for _ in range(n):
            hi = v & 0x80
            v = ((v << 1) & 0xFF) ^ (poly if hi else 0)
        return v
    Ms = []
    for i in range(4):
        eqs = []
        for inp, outp in samples:
            for pos in range(4):
                o = outp[4 * i + pos] if mode == "col" else outp[4 * pos + i]
                for k in range(8):
                    ob = (o >> (7 - k)) & 1
                    coefbits = 0
                    for j in range(4):
                        x = inp[4 * j + pos] if mode == "col" else inp[4 * pos + j]
                        for b in range(8):
                            mjb = (xt(x, b) >> (7 - k)) & 1
                            if mjb:
                                coefbits |= 1 << (nv - 1 - ((i * 4 + j) * 8 + b))
                    eqs.append((coefbits, ob))
        sol = solve_lin(eqs, nv)
        if sol is None:
            return None
        row = []
        for j in range(4):
            v = 0
            for b in range(8):
                if sol[(i * 4 + j) * 8 + b]:
                    v |= 1 << (7 - b)
            row.append(v)
        Ms.append(row)
    return Ms


def verify(M, samples, mode, poly):
    ok = 0
    for inp, outp in samples:
        good = True
        for i in range(4):
            for pos in range(4):
                acc = 0
                for j in range(4):
                    x = inp[4 * j + pos] if mode == "col" else inp[4 * pos + j]
                    acc ^= gmul(M[i][j], x, poly)
                o = outp[4 * i + pos] if mode == "col" else outp[4 * pos + i]
                if acc != o:
                    good = False
                    break
            if not good:
                break
        ok += good
    return ok


def main():
    R = load_rounds()
    pairs_1172 = [(rd["quad"][-1][1], rd["m1"]) for rd in R
                  if "quad" in rd and "m1" in rd]
    pairs_1177 = [(rd["m1"], rd["m2"]) for rd in R
                  if "m1" in rd and "m2" in rd and "quad" in rd]
    tail = [(rd["sr_in"], rd["m1"]) for rd in R if rd.get("tail")]
    print("samples: 0x1172 %d, 0x1177 %d, tail %d"
          % (len(pairs_1172), len(pairs_1177), len(tail)))
    for name, smp in (("0x1172", pairs_1172), ("0x1177", pairs_1177),
                      ("tail", tail)):
        for mode in ("col", "row"):
            for poly in POLYS:
                tr = smp[:9]
                te = smp[9:]
                M = fit(tr, mode, poly)
                if M is None:
                    continue
                ok_tr = verify(M, tr, mode, poly)
                ok_te = verify(M, te, mode, poly)
                if ok_tr == len(tr) and ok_te == len(te):
                    print("%s mode=%s poly=%#05x FULL FIT %d/%d train, %d/%d test"
                          % (name, mode, poly, ok_tr, len(tr), ok_te, len(te)))
                    print("   M =", [[hex(x) for x in row] for row in M])


if __name__ == "__main__":
    main()
