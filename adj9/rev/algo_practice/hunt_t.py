"""hunt_t.py — structural hunt for the whitening S-box T.

The cipher uses S(v) = T[v] ^ 0x55 (whiten_chunk) and round keys KB ^ 0x55;
both raw T and the ^0x55 form are tested.

Battery 1 (structure): bijection, involution, fixed points, affinity,
                       linearity of S ^ S(0), whether T is a bit rotation/
                       reversal family, differential uniformity (design smell).
Battery 2 (power-map affine equivalence): for each irreducible degree-8 poly
                       (30) and each exponent e in 1..255, is S(v) affine
                       equivalent to v^e, i.e. S(v) = M . (v^e) ^ c with M an
                       8x8 GF(2) matrix?  (Input scaling folds into M, so
                       c=1 suffices.)  Solve M by GF(2) Gaussian elimination,
                       verify on all 256 points.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "pure_signer"))
from pure_sign import T  # noqa: E402

SBOX = [T[v] ^ 0x55 for v in range(256)]      # the form the cipher uses
RAW = list(T)


def gf_mul(a, b, m):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= m | 0x100
    return r


def gf_pow(a, e, m):
    r = 1
    while e:
        if e & 1:
            r = gf_mul(r, a, m)
        a = gf_mul(a, a, m)
        e >>= 1
    return r


def irreducible_polys():
    out = []
    for p in range(256):
        m = p | 0x100
        if gf_pow(2, 255, m) != 1:
            continue
        if any(gf_pow(2, d, m) == 1 for d in (1, 3, 5, 15)):
            continue
        out.append(p)
    return out


def solve_affine(base, sbox):
    """Is sbox(v) = M.(base(v) ^ base(0)) ^ sbox(0) for an 8x8 GF(2) M?
    Returns M rows or None; verified on all 256 points."""
    b0 = base[0] ^ base[0]              # 0
    rows_in = []
    for v in range(256):
        rows_in.append(base[v] ^ base[0])
    # unknowns: 64 bits m[j][i].  Equations: for each v, out_j =
    # sum_i m[j][i].in_i(v).  Solve per output bit with bit-parallel rows.
    eqs = []                            # (in-mask, out-bits)
    for v in range(256):
        eqs.append((rows_in[v], sbox[v] ^ sbox[0]))
    # rank check: treat unknowns m[j][*] independently per bit j
    M = []
    for j in range(8):
        piv = {}
        ok = True
        for mask, out in eqs:
            if mask == 0:
                if out >> j & 1:
                    ok = False          # inconsistent (constant term needed)
                    break
                continue
            cur_m, cur_o = mask, (out >> j) & 1
            while cur_m:
                h = cur_m.bit_length() - 1
                if h in piv:
                    pm, po = piv[h]
                    cur_m ^= pm
                    cur_o ^= po
                else:
                    piv[h] = (cur_m, cur_o)
                    break
            else:
                if cur_o:
                    ok = False
                    break
        if not ok:
            return None
        # back-substitute to full row form
        for h in sorted(piv):
            pm, po = piv[h]
            for h2 in sorted(piv):
                if h2 > h:
                    pm2, po2 = piv[h2]
                    if pm2 >> h & 1:
                        pm ^= pm2
                        po ^= po2
            # can't easily reduce upward in dict order; redo below
        # simpler: rebuild full RREF
        rows = [(m, o) for m, o in piv.values()]
        changed = True
        while changed:
            changed = False
            for a in range(len(rows)):
                for b in range(len(rows)):
                    if a != b:
                        ha = rows[a][0].bit_length() - 1
                        if rows[b][0] >> ha & 1:
                            rows[b] = (rows[b][0] ^ rows[a][0],
                                       rows[b][1] ^ rows[a][1])
                            changed = True
        # if any reduced row has zero mask and 1 -> inconsistent (handled)
        row = 0
        for m, o in rows:
            h = m.bit_length() - 1
            if o:
                row |= 1 << h
        # row[j] = bits i with m[j][i] = 1? we solved per output bit j with
        # unknown vector = row i of M -> transpose carefully below.
        M.append(row)
    # M[j] currently: bit h set means unknown x_h = 1 where h indexes the
    # INPUT bit i (pivots keyed by input bit).  So M[j] bit i = m[j][i]... yes.
    # verify on all 256
    for v in range(256):
        y = sbox[0]
        for j in range(8):
            b = 0
            for i in range(8):
                if M[j] >> i & 1:
                    b ^= (rows_in[v] >> i) & 1
            y |= b << j
        if y != sbox[v]:
            return None
    return M


def battery1(name, s):
    print("== battery 1: %s ==" % name)
    bij = len(set(s)) == 256
    inv = all(s[s[v]] == v for v in range(256))
    fixes = sum(1 for v in range(256) if s[v] == v)
    # affinity: s(a^b) ^ s(0) == (s(a)^s(0)) ^ (s(b)^s(0))?
    aff = all((s[a ^ b] ^ s[0]) == ((s[a] ^ s[0]) ^ (s[b] ^ s[0]))
              for a in range(256) for b in range(256))
    # differential uniformity
    from collections import Counter
    du = 0
    for dlt in range(1, 256):
        c = Counter(s[v] ^ s[v ^ dlt] for v in range(256))
        du = max(du, max(c.values()))
    print("  bijective: %s  involution: %s  fixed points: %d  affine: %s  "
          "diff-uniformity: %d" % (bij, inv, fixes, aff, du))
    return bij, inv, aff, du


def battery2(name, s, irreds):
    print("== battery 2: %s — affine equivalence to power maps ==" % name)
    hits = []
    for p in irreds:
        m = p | 0x100
        base_tab = {}
        for e in range(1, 256):
            base = [gf_pow(v, e, m) for v in range(256)]
            if len(set(base)) != 256 and e != 0:
                pass                        # non-bijective power: still test
            M = solve_affine(base, s)
            if M is not None:
                hits.append((p, e, M))
                print("  HIT: poly=0x%02X e=%d  M rows: %s"
                      % (p, e, " ".join("%02x" % r for r in M)))
    if not hits:
        print("  no (poly, exponent) with S affine-equivalent to v^e")
    return hits


def main():
    irreds = irreducible_polys()
    print("%d irreducible degree-8 polys" % len(irreds))
    for name, s in (("S = T^0x55 (cipher form)", SBOX),
                    ("raw T", RAW)):
        battery1(name, s)
        hits = battery2(name, s, irreds)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
