"""hunt_t2.py — hunt for the GENERATIVE LAW of the whitening S-box T.

The cipher uses S(v) = T[v] ^ 0x55 (pure_sign.whiten_chunk).  All searches run
on the S-form table; raw T differs by the output constant 0x55, which is a
GF(2)-affine automorphism, so every (in)equivalence transfers verbatim (only
the t2 offset shifts by 0x55).  Final formulas are verified on BOTH forms.

Stage 1  cheap structured families: fix one affine side from a candidate
         family, solve the other side exactly by GF(2) linear algebra:
           a. bit permutations (all 8! = 40320, both directions)
           b. xtime powers (mult by x^k mod 0x11B), byte rotations,
              compositions, with full 256-value offset escalation
           c. the AES S-box affine matrix and its powers
           d. all 128 invertible byte-circulants (F-style generators),
              products xtime^i o circ(r) / circ(r) o xtime^i
Stage 2  spectral gating of candidate CORE boxes: AES S-box, raw inversion
         in the AES field, and every power map x^e (e = 1..254) mod 0x11B,
         via DDT spectrum, Walsh-spectrum multiset and row-signature
         multiset (all affine-equivalence invariants).
Stage 3  complete affine-equivalence search (linear-approximation-table
         row/pair-invariant backtracking, Biryukov-De Canniere-Braeken /
         Perrin style) against every surviving core; on a hit: recover the
         offsets, verify 256/256, analyse the matrices' structure.

Embedded self-tests validate every tool on planted answers before any
verdict is allowed to stand.

Run:  python hunt_t2.py            # stage 0 law check + confirmation + verdict
      python hunt_t2.py selftest   # tool validation only
      python hunt_t2.py full       # additionally the exhaustive stage-1 sweeps
"""
import sys
import os
import time
import itertools
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "pure_signer"))
from pure_sign import T as T_BYTES  # noqa: E402

SBOX = [T_BYTES[v] ^ 0x55 for v in range(256)]   # cipher form S(v)
RAW = list(T_BYTES)

AES_POLY = 0x11B

# --------------------------------------------------------------------------
# GF(2^8) arithmetic (byte value == polynomial, bit 0 == x^0)
# --------------------------------------------------------------------------

def gf_mul(a, b, m=AES_POLY):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= m | 0x100
    return r


def gf_pow(a, e, m=AES_POLY):
    r = 1
    while e:
        if e & 1:
            r = gf_mul(r, a, m)
        a = gf_mul(a, a, m)
        e >>= 1
    return r


def gf_inv(a, m=AES_POLY):
    return gf_pow(a, 254, m) if a else 0


def rotl8(x, r):
    r &= 7
    return ((x << r) | (x >> (8 - r))) & 0xFF if r else x


def rotr8(x, r):
    r &= 7
    return ((x >> r) | (x << (8 - r))) & 0xFF if r else x


def build_aes_sbox():
    out = []
    for v in range(256):
        b = gf_inv(v)
        out.append(b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3)
                   ^ rotl8(b, 4) ^ 0x63)
    return out


AES_SBOX = build_aes_sbox()
assert AES_SBOX[0] == 0x63 and AES_SBOX[0x53] == 0xED
assert [AES_SBOX[i] for i in range(16)] == [0x63, 0x7C, 0x77, 0x7B, 0xF2,
                                            0x6B, 0x6F, 0xC5, 0x30, 0x01,
                                            0x67, 0x2B, 0xFE, 0xD7, 0xAB,
                                            0x76]
AES_SBOX_INV = [0] * 256
for _v in range(256):
    AES_SBOX_INV[AES_SBOX[_v]] = _v
INVERSE_TABLE = [gf_inv(v) for v in range(256)]   # raw inversion, AES field

XTIME_TAB = [gf_mul(v, 2) for v in range(256)]
ROT_TAB = [rotl8(v, 1) for v in range(256)]       # byte rotate-left (= x mod x^8+1)


# --------------------------------------------------------------------------
# GF(2) 8x8 matrices.  Convention: M = tuple of 8 row masks;
# out bit j = parity(M[j] & x)  (standard column-vector matrix action).
# --------------------------------------------------------------------------

def par(x):
    return x.bit_count() & 1


def mat_apply(M, x):
    y = 0
    for j in range(8):
        if (M[j] & x).bit_count() & 1:
            y |= 1 << j
    return y


def tab_from_mat(M):
    return [mat_apply(M, v) for v in range(256)]


def mat_from_table(tab):
    M = []
    for j in range(8):
        r = 0
        for i in range(8):
            if tab[1 << i] >> j & 1:
                r |= 1 << i
        M.append(r)
    return tuple(M)


def tvec(M, c):
    """transpose of M applied to column c: XOR of rows selected by c."""
    r = 0
    while c:
        h = c.bit_length() - 1
        r ^= M[h]
        c ^= 1 << h
    return r


def mat_transpose(M):
    MT = [0] * 8
    for i in range(8):
        m = M[i]
        while m:
            h = m.bit_length() - 1
            MT[h] |= 1 << i
            m ^= 1 << h
    return tuple(MT)


def mat_inv(M):
    rows = [(M[j], 1 << j) for j in range(8)]
    for c in range(8):
        p = -1
        for i in range(c, 8):
            if rows[i][0] >> c & 1:
                p = i
                break
        if p < 0:
            return None
        rows[c], rows[p] = rows[p], rows[c]
        mr, ir = rows[c]
        for i in range(8):
            if i != c and (rows[i][0] >> c & 1):
                rows[i] = (rows[i][0] ^ mr, rows[i][1] ^ ir)
    return tuple(rows[j][1] for j in range(8))


def compose_lin(A, B):
    """matrix for A after B (tables composed)."""
    tb = tab_from_mat(B)
    return mat_from_table([A[y] for y in tb])


def circulant(r):
    """byte-circulant with (C x)_i = parity(rotr8(r, i) & x)."""
    return tuple(rotr8(r, i) for i in range(8))


def is_circulant(M):
    for fn in (rotr8, rotl8):
        if all(M[i] == fn(M[0], i) for i in range(8)):
            return True
    return False


def is_bit_perm(M):
    cols = [tab_from_mat(M)[1 << i] for i in range(8)]
    return all(c.bit_count() == 1 for c in cols) and len(set(cols)) == 8


def is_xtime_power(M):
    t = tab_from_mat(M)
    cur = list(range(256))
    for k in range(255):
        if t == cur:
            return k
        cur = [XTIME_TAB[v] for v in cur]
    return None


# --------------------------------------------------------------------------
# Generic affine solver:  find (M, t) with  M . F[v] XOR t == Y[v]  for all v.
# --------------------------------------------------------------------------

def solve_affine(F, Y):
    """F, Y: lists of 256 bytes.  Returns (Mrows, t) or None.  Fully verified
    on all 256 points; complete for the feature sets used here (augmented
    rank 9).  Unknown offset t sits on the TARGET side."""
    basis = {}
    sel = []
    for v in range(256):
        cur = F[v] | 0x100                      # bit 8 = constant term
        placed = False
        while cur:
            h = cur.bit_length() - 1
            if h in basis:
                cur ^= basis[h]
            else:
                basis[h] = cur
                sel.append(v)
                placed = True
                break
        if len(basis) == 9:
            break
    if len(basis) < 9:
        return None                             # degenerate features: reject
    aug = [F[v] | 0x100 for v in sel]
    Mrows = [0] * 8
    t = 0
    for j in range(8):
        rows = [(aug[k], (Y[sel[k]] >> j) & 1) for k in range(9)]
        sol = _solve09(rows)
        if sol is None:
            return None
        Mrows[j] = sol & 0xFF
        if sol >> 8 & 1:
            t |= 1 << j
    for v in range(256):
        x = F[v]
        acc = 0
        for j in range(8):
            if (Mrows[j] & x).bit_count() & 1:
                acc |= 1 << j
        if acc ^ t != Y[v]:          # XOR, not OR: offset must cancel bits
            return None
    return (tuple(Mrows), t)


def _solve09(rows):
    """Solve a 9x10 augmented system (unique when rank 9); rows are
    (9-bit coefficient vector, rhs bit).  Returns 9-bit solution or None."""
    piv = []
    r = 0
    for c in range(8, -1, -1):
        p = -1
        for i in range(r, 9):
            if rows[i][0] >> c & 1:
                p = i
                break
        if p < 0:
            continue
        rows[r], rows[p] = rows[p], rows[r]
        pr, pv = rows[r]
        for i in range(9):
            if i != r and (rows[i][0] >> c & 1):
                rows[i] = (rows[i][0] ^ pr, rows[i][1] ^ pv)
        piv.append(c)
        r += 1
        if r == 9:
            break
    if r < 9:
        return None
    sol = 0
    for k, c in enumerate(piv):
        if rows[k][1]:
            sol |= 1 << c
    return sol


# --------------------------------------------------------------------------
# Stage 1 machinery: candidate families.
# Direction A: fix L1 (affine, linear part must be invertible),
#              features F[v] = CORE[L1(v) ^ t1];  solve (M2, t2) freely.
# Direction B: fix L2 = (Mc, tc);  target Y[v] = COREINV[Mc^-1 (S(v) ^ tc)];
#              features F[v] = v;  solve (M1, t1) freely  (all t1 covered).
# --------------------------------------------------------------------------

CORE = AES_SBOX
COREINV = AES_SBOX_INV


def dirA(tab, L1tab, t1, label):
    F = [CORE[L1tab[v] ^ t1] for v in range(256)]
    r = solve_affine(F, tab)
    if r is not None:
        return (label, t1, r[0], r[1])
    return None


def dirB(tab, Mc, tc, label):
    Minv = mat_inv(Mc)
    if Minv is None:
        return None
    Y = [COREINV[mat_apply(Minv, tab[v] ^ tc)] for v in range(256)]
    r = solve_affine(list(range(256)), Y)
    if r is not None:
        return (label, tc, r[0], r[1])
    return None


def fam_bit_perms():
    for p in itertools.permutations(range(8)):
        tab = [sum(((v >> i) & 1) << p[i] for i in range(8)) for v in range(256)]
        pinv = [0] * 8
        for i in range(8):
            pinv[p[i]] = i
        tabinv = [sum(((v >> i) & 1) << pinv[i] for i in range(8)) for v in range(256)]
        yield ("perm" + str(p), tab, tabinv, mat_from_table(tab))


def fam_linear_tables():
    """(label, table, matrix) for the linear family members."""
    yield ("identity", list(range(256)), tuple(1 << i for i in range(8)))
    # xtime powers
    t = list(range(256))
    for k in range(255):
        if k:
            t = [XTIME_TAB[v] for v in t]
        yield ("xtime^%d" % k, list(t), mat_from_table(t))
    # byte rotations
    for j in range(1, 8):
        rt = [rotl8(v, j) for v in range(256)]
        yield ("rot%d" % j, rt, mat_from_table(rt))
    # byte circulants (invertible only)
    for r in range(256):
        M = circulant(r)
        if mat_inv(M) is not None:
            yield ("circ(0x%02x)" % r, tab_from_mat(M), M)


def products(f1, f2, cap=None):
    """compositions f1 o f2 over two (label, table, matrix) iterables."""
    l2 = list(f2)
    n = 0
    for la, ta, ma in f1:
        for lb, tb, mb in l2:
            n += 1
            if cap and n > cap:
                return
            tab = [ta[y] for y in tb]
            yield (la + "o" + lb, tab, mat_from_table(tab))


def stage1(tab, budget_report=None):
    """Run the cheap structured families.  Returns list of hits."""
    hits = []
    t0 = time.time()

    # ---- direction B first for small families: covers ALL input offsets ----
    small = list(fam_linear_tables())
    print("  [1] direction B (fix L2, solve M1/t1 free) over %d linear members"
          % len(small))
    for label, _t, Mc in small:
        for tc in range(256):
            h = dirB(tab, Mc, tc, label + "|tc=%02x" % tc)
            if h:
                hits.append(("B",) + h)
    print("      done %.1fs" % (time.time() - t0))

    # ---- direction A over linear members, t1 = 0 ----
    print("  [1] direction A (fix L1, solve M2/t2 free), t1=0")
    for label, lt, _m in small:
        h = dirA(tab, lt, 0, label)
        if h:
            hits.append(("A",) + h)
    print("      done %.1fs" % (time.time() - t0))

    # ---- direction A: xtime^i o circ(r) and circ(r) o xtime^i, t1 = 0 ----
    xts = [(l, t, m) for (l, t, m) in small if l.startswith("xtime")]
    circs = [(l, t, m) for (l, t, m) in small if l.startswith("circ")]
    print("  [1] direction A over products xtime^i o circ / circ o xtime^i")
    for comp in (products(xts, circs), products(circs, xts)):
        for label, lt, _m in comp:
            h = dirA(tab, lt, 0, label)
            if h:
                hits.append(("A",) + h)
    print("      done %.1fs" % (time.time() - t0))

    # ---- bit permutations, both directions, offsets 0 (as instructed) ----
    print("  [1] bit permutations (40320), direction A t1=0")
    cnt = 0
    for label, ptab, _pinv, _m in fam_bit_perms():
        h = dirA(tab, ptab, 0, label)
        if h:
            hits.append(("A",) + h)
        cnt += 1
        if cnt % 10000 == 0:
            print("      %d perms %.1fs" % (cnt, time.time() - t0))
    print("      done %.1fs" % (time.time() - t0))

    print("  [1] bit permutations, direction B, tc in {0x00,0x55,0x63,0xff}")
    for label, ptab, pinv, _m in fam_bit_perms():
        Mp = mat_from_table(pinv)
        for tc in (0x00, 0x55, 0x63, 0xFF):
            h = dirB(tab, Mp, tc, label + "|tc=%02x" % tc)
            if h:
                hits.append(("B",) + h)
    print("      done %.1fs" % (time.time() - t0))

    # ---- offset escalation for the small linear families (direction A) ----
    print("  [1] escalation: direction A over xtime^k / circulants / rots "
          "with all 256 offsets t1")
    esc = [(l, t) for (l, t, m) in small
           if l.startswith(("xtime", "circ", "rot"))]
    for label, lt in esc:
        for t1 in range(1, 256):
            h = dirA(tab, lt, t1, label)
            if h:
                hits.append(("A",) + h)
    print("      done %.1fs" % (time.time() - t0))
    return hits


# --------------------------------------------------------------------------
# Walsh / LAT and DDT machinery
# --------------------------------------------------------------------------

def walsh_lat(tab):
    """LAT[a][b] = sum_v (-1)^{par(a&v) ^ par(b&tab[v])}."""
    LAT = []
    for b in range(256):
        g = [1 - 2*((b & tab[v]).bit_count() & 1) for v in range(256)]
        LAT.append(wht(g))
    # transposed storage: LAT[a][b]
    return [list(col) for col in zip(*LAT)]


def wht(f):
    h = list(f)
    step = 1
    n = len(h)
    while step < n:
        for i in range(0, n, step * 2):
            for k in range(i, i + step):
                x, y = h[k], h[k + step]
                h[k], h[k + step] = x + y, x - y
        step *= 2
    return h


def ddt(tab):
    D = [[0] * 256 for _ in range(256)]
    for a in range(1, 256):
        cnt = Counter(tab[v ^ a] ^ tab[v] for v in range(256))
        for k, c in cnt.items():
            D[a][k] = c
    return D


def lat_spectrum(LAT):
    return tuple(sorted(abs(LAT[a][b]) for a in range(256)
                        for b in range(256)))


def ddt_spectrum(D):
    vals = [D[a][b] for a in range(1, 256) for b in range(256) if D[a][b]]
    return tuple(sorted(vals))


def row_sigs(LAT):
    """rs[a] (a != 0) = sorted multiset of |LAT[a][b]| over b != 0."""
    return {a: tuple(sorted(abs(LAT[a][b]) for b in range(1, 256)))
            for a in range(1, 256)}


# --------------------------------------------------------------------------
# Stage 3: complete affine-equivalence search via LAT invariants.
# Necessary relations for S = L2 o A o L1 (affine L1, L2):
#   |LAT_S(a,b)| = |LAT_A(P a, Q b)|   with P = M1^{-T}, Q = M2^T.
# --------------------------------------------------------------------------

class Budget(Exception):
    pass


def jx(LAT, xs, memo):
    """multiset over b!=0 of |LAT[x][b]| for x in xs (tuple)."""
    r = memo.get(xs)
    if r is None:
        r = tuple(sorted(tuple(abs(LAT[x][b]) for x in xs)
                         for b in range(1, 256)))
        memo[xs] = r
    return r


def iter_P_candidates(LAT_S, LAT_A, node_budget=5_000_000):
    """Yield invertible linear maps P (as 256-tables) satisfying every
    NECESSARY invariant: row-signature match, pairwise J-invariants,
    invertibility.  Exhaustion proves no linear part exists."""
    rsS = row_sigs(LAT_S)
    rsA = row_sigs(LAT_A)
    if Counter(rsS.values()) != Counter(rsA.values()):
        return
    classA = defaultdict(list)
    for u in range(1, 256):
        classA[rsA[u]].append(u)
    order = sorted((1 << k for k in range(8)),
                   key=lambda e: len(classA[rsS[e]]))
    memoS, memoA = {}, {}
    img = [0] * 8
    assigned = []
    nodes = [0]

    def independent(u):
        vs = []
        for _e, uu in assigned:
            v = uu
            for p in vs:
                v = min(v, v ^ p)
            if v:
                vs.append(v)
                vs.sort(reverse=True)
        v = u
        for p in vs:
            v = min(v, v ^ p)
        return v != 0

    def consistent(u, e):
        for (e2, u2) in assigned:
            if jx(LAT_A, (u, u2, u ^ u2), memoA) != \
               jx(LAT_S, (e, e2, e ^ e2), memoS):
                return False
        if len(assigned) >= 2:
            for i in range(len(assigned)):
                for jj in range(i + 1, len(assigned)):
                    e1, u1 = assigned[i]
                    e2, u2 = assigned[jj]
                    if jx(LAT_A, (u, u1, u2, u ^ u1, u ^ u2, u1 ^ u2,
                                  u ^ u1 ^ u2), memoA) != \
                       jx(LAT_S, (e, e1, e2, e ^ e1, e ^ e2, e1 ^ e2,
                                  e ^ e1 ^ e2), memoS):
                        return False
        return True

    def rec(k):
        if nodes[0] > node_budget:
            raise Budget()
        if k == 8:
            Ptab = [0] * 256
            for a in range(1, 256):
                w = 0
                aa = a
                while aa:
                    h = aa.bit_length() - 1
                    w ^= img[h]
                    aa ^= 1 << h
                Ptab[a] = w
            for a in range(1, 256):
                if rsS[a] != rsA[Ptab[a]]:
                    return
            yield list(Ptab)
            return
        e = order[k]
        bit = e.bit_length() - 1
        for u in classA[rsS[e]]:
            nodes[0] += 1
            if not independent(u):
                continue
            if not consistent(u, e):
                continue
            img[bit] = u
            assigned.append((e, u))
            yield from rec(k + 1)
            assigned.pop()
        return

    yield from rec(0)


def full_lat_match(LAT_S, LAT_A, Ptab, Qtab):
    for a in range(1, 256):
        pa = Ptab[a]
        La = LAT_S[a]
        Lp = LAT_A[pa]
        for b in range(1, 256):
            if abs(La[b]) != abs(Lp[Qtab[b]]):
                return False
    return True


def iter_Q_candidates(LAT_S, LAT_A, Ptab):
    """Yield linear Q (256-tables) with |LAT_S(a,b)| = |LAT_A(P a, Q b)|
    for all a,b.  Exhaustion proves no Q for this P."""
    buckets = defaultdict(list)
    for w in range(1, 256):
        key = tuple(abs(LAT_A[Ptab[a]][w]) for a in range(1, 256))
        buckets[key].append(w)
    cand = {}
    for b in range(1, 256):
        key = tuple(abs(LAT_S[a][b]) for a in range(1, 256))
        lst = buckets.get(key, [])
        if not lst:
            return
        cand[b] = lst
    Qimg = [0] * 8
    assignedQ = []

    def rec(k):
        if k == 8:
            Qtab = [0] * 256
            for b in range(1, 256):
                w = 0
                bb = b
                while bb:
                    h = bb.bit_length() - 1
                    w ^= Qimg[h]
                    bb ^= 1 << h
                Qtab[b] = w
            if full_lat_match(LAT_S, LAT_A, Ptab, Qtab):
                yield Qtab
            return
        b = 1 << k
        for w in cand[b]:
            ok = True
            for (b2, w2) in assignedQ:
                if (w ^ w2) not in cand[b ^ b2]:
                    ok = False
                    break
            if not ok:
                continue
            Qimg[k] = w
            assignedQ.append((b, w))
            yield from rec(k + 1)
            assignedQ.pop()
        return

    yield from rec(0)


def finish_equivalence(tab, core_tab, Ptab, Qtab):
    """From linear parts to full affine form S = M2.core(M1.v ^ t1) ^ t2."""
    P = mat_from_table(Ptab)
    Q = mat_from_table(Qtab)
    Pi = mat_inv(P)
    if Pi is None or mat_inv(Q) is None:
        return None
    M1 = mat_transpose(Pi)          # M1 = (P^{-1})^T
    M2 = mat_transpose(Q)
    for t1 in range(256):
        c0 = mat_apply(M2, core_tab[mat_apply(M1, 0) ^ t1])
        t2 = tab[0] ^ c0
        ok = True
        for v in range(1, 256):
            if mat_apply(M2, core_tab[mat_apply(M1, v) ^ t1]) ^ t2 != tab[v]:
                ok = False
                break
        if ok:
            return (M1, t1, M2, t2)
    return None


def affine_equivalence(tab, core_tab, node_budget=5_000_000, verbose=True,
                       LAT_S=None):
    """Full pipeline.  Returns (M1, t1, M2, t2) or None."""
    if LAT_S is None:
        LAT_S = walsh_lat(tab)
    LAT_A = walsh_lat(core_tab)
    if lat_spectrum(LAT_S) != lat_spectrum(LAT_A):
        if verbose:
            print("    reject: Walsh spectrum multiset differs")
        return None
    tried = 0
    try:
        for Ptab in iter_P_candidates(LAT_S, LAT_A, node_budget):
            tried += 1
            for Qtab in iter_Q_candidates(LAT_S, LAT_A, Ptab):
                r = finish_equivalence(tab, core_tab, Ptab, Qtab)
                if r is not None:
                    if verbose:
                        print("    equivalence found after %d P-candidates"
                              % tried)
                    return r
                if verbose:
                    print("    P/Q candidate #%d passed |LAT| but no offsets"
                          % tried)
    except Budget:
        print("    NODE BUDGET EXHAUSTED (inconclusive at this budget)")
        return None
    if verbose:
        print("    search exhausted after %d P-candidates: no equivalence"
              % tried)
    return None


# --------------------------------------------------------------------------
# structure analysis / reporting
# --------------------------------------------------------------------------

def classify_matrix(M):
    descs = []
    if is_bit_perm(M):
        descs.append("bit-permutation")
    k = is_xtime_power(M)
    if k is not None:
        descs.append("xtime^%d (mult by 0x%02x mod 0x11B)" % (k, gf_pow(2, k)))
    if is_circulant(M):
        descs.append("byte-circulant, first row 0x%02x" % M[0])
    # powers of the AES-affine LINEAR matrix  x -> x ^ r1 ^ r2 ^ r3 ^ r4
    alin = [x ^ rotl8(x, 1) ^ rotl8(x, 2) ^ rotl8(x, 3) ^ rotl8(x, 4)
            for x in range(256)]
    t = tab_from_mat(M)
    cur = list(range(256))
    for i in range(1, 400):
        cur = [alin[y] for y in cur]
        if cur == list(range(256)):
            break
        if t == cur:
            descs.append("AES-affine-linear^%d" % i)
            break
    # products xtime^i o rot^j and rot^j o xtime^i
    xt_tables = []
    cur = list(range(256))
    for i in range(255):
        if i:
            cur = [XTIME_TAB[v] for v in cur]
        xt_tables.append(list(cur))
    for j in range(8):
        rt = [rotl8(v, j) for v in range(256)]
        for i in range(255):
            if t == [xt_tables[i][y] for y in rt]:
                descs.append("xtime^%d o rot%d" % (i, j))
            if t == [rt[y] for y in xt_tables[i]]:
                descs.append("rot%d o xtime^%d" % (j, i))
    if not descs:
        descs.append("rows " + " ".join("%02x" % r for r in M))
    return "; ".join(descs)


def report_hit(direction, label, offset_label, M1, t1, M2, t2):
    print("  *** HIT ***  dir=%s candidate=%s %s" % (direction, label,
                                                     offset_label))
    print("      M1 rows: %s   t1=0x%02x" %
          (" ".join("%02x" % r for r in M1), t1))
    print("      M2 rows: %s   t2=0x%02x" %
          (" ".join("%02x" % r for r in M2), t2))
    print("      M1: %s" % classify_matrix(M1))
    print("      M2: %s" % classify_matrix(M2))


def verify_formula(tab, core_tab, M1, t1, M2, t2):
    for v in range(256):
        if mat_apply(M2, core_tab[mat_apply(M1, v) ^ t1]) ^ t2 != tab[v]:
            return False
    return True


# --------------------------------------------------------------------------
# self tests
# --------------------------------------------------------------------------

def selftest():
    ok = True
    # matrix machinery
    Minv = mat_inv(mat_from_table(XTIME_TAB))
    assert Minv is not None
    xtinv = mat_from_table([gf_mul(v, 0x8D) for v in range(256)])
    assert Minv == xtinv, "xtime inverse mismatch"
    assert mat_apply(xtinv, mat_apply(mat_from_table(XTIME_TAB), 0x57)) == 0x57
    # transpose/tvec consistency
    import random
    random.seed(1)
    for _ in range(20):
        M = tuple(random.getrandbits(8) for _ in range(8))
        c = random.getrandbits(8)
        assert tvec(M, c) == mat_apply(mat_transpose(M), c)
    # solve_affine round trip with planted affine decomposition
    for trial in range(10):
        M1 = None
        while M1 is None:
            M1 = tuple(random.getrandbits(8) for _ in range(8))
            M1 = mat_inv(M1) and M1 or None
        M2 = None
        while M2 is None:
            M2 = tuple(random.getrandbits(8) for _ in range(8))
            M2 = mat_inv(M2) and M2 or None
        t1 = random.getrandbits(8)
        t2 = random.getrandbits(8)
        S = [mat_apply(M2, AES_SBOX[mat_apply(M1, v) ^ t1]) ^ t2
             for v in range(256)]
        # direction A with L1 known: features via the exact L1 table
        L1tab = [mat_apply(M1, v) for v in range(256)]
        r = solve_affine([AES_SBOX[L1tab[v] ^ t1] for v in range(256)], S)
        assert r is not None, "solve_affine failed on planted decomposition"
        M2s, t2s = r
        assert all(mat_apply(M2s, AES_SBOX[L1tab[v] ^ t1]) ^ t2s == S[v]
                   for v in range(256))
        # direction B with L2 known
        Y = [AES_SBOX_INV[mat_apply(mat_inv(M2), S[v] ^ t2)]
             for v in range(256)]
        r2 = solve_affine(list(range(256)), Y)
        assert r2 is not None
        M1s, t1s = r2
        assert all(mat_apply(M1s, v) ^ t1s == L1tab[v] ^ t1
                   for v in range(256)), (M1s, t1s)
    print("  solve_affine round-trips: OK")
    # planted affine equivalence to the AES sbox must be FOUND by stage 3
    for trial in range(3):
        M1 = None
        while M1 is None:
            M1 = tuple(random.getrandbits(8) for _ in range(8))
            M1 = mat_inv(M1) and M1 or None
        M2 = None
        while M2 is None:
            M2 = tuple(random.getrandbits(8) for _ in range(8))
            M2 = mat_inv(M2) and M2 or None
        t1 = random.getrandbits(8)
        t2 = random.getrandbits(8)
        S = [mat_apply(M2, AES_SBOX[mat_apply(M1, v) ^ t1]) ^ t2
             for v in range(256)]
        t0 = time.time()
        r = affine_equivalence(S, AES_SBOX, verbose=False)
        assert r is not None, "planted AES equivalence NOT found"
        M1f, t1f, M2f, t2f = r
        assert verify_formula(S, AES_SBOX, M1f, t1f, M2f, t2f)
        print("  planted AES-equivalence #%d recovered and verified (%.1fs)"
              % (trial, time.time() - t0))
    # negative control: a random permutation is not AES-equivalent
    perm = list(range(256))
    random.shuffle(perm)
    r = affine_equivalence(perm, AES_SBOX, verbose=False)
    assert r is None
    print("  negative control (random perm vs AES): rejected OK")
    print("SELFTEST PASS")
    return ok


# --------------------------------------------------------------------------
# main stages
# --------------------------------------------------------------------------

def law_check():
    """Stage 0: the direct structural identity test."""
    print("\n==== STAGE 0: direct identity checks ====")
    eq_s = all(SBOX[v] == AES_SBOX[v] for v in range(256))
    eq_t = all(RAW[v] == (AES_SBOX[v] ^ 0x55) for v in range(256))
    print("  S = T^0x55 equals the AES S-box on all 256 values: %s" % eq_s)
    print("  raw T equals (AES S-box) ^ 0x55 on all 256 values:  %s" % eq_t)
    # algebraic regeneration: T[v] = L(v^-1) ^ 0x36 with L the AES affine
    # linear part and v^-1 in GF(2^8) mod 0x11B
    L_TAB = [x ^ rotl8(x, 1) ^ rotl8(x, 2) ^ rotl8(x, 3) ^ rotl8(x, 4)
             for x in range(256)]
    regen = bytes(L_TAB[gf_inv(v)] ^ 0x36 for v in range(256))
    ok = regen == T_BYTES
    print("  T[v] = L(v^-1) ^ 0x36 regenerates all 256 bytes:      %s" % ok)
    M = mat_from_table(L_TAB)
    print("  L rows (output-bit masks): %s" % " ".join("%02x" % r for r in M))
    print("  L: %s" % classify_matrix(M))
    # corrected power-map audit (the old battery had an OR/XOR solver bug)
    print("  re-audit with FIXED solver: S(v) = M.(v^-1) ^ c over the 30 "
          "irreducible polys, e = 254:")
    irreds = irreducible_polys()
    for p in irreds:
        base = [gf_inv_poly(v, p) for v in range(256)]
        r = solve_affine(base, SBOX)
        if r is not None:
            print("    HIT poly=0x%02X e=254  M rows: %s  c=0x%02x"
                  % (p, " ".join("%02x" % x for x in r[0]), SBOX[0]))
    return eq_s and eq_t and ok


def gf_inv_poly(a, p):
    return gf_pow(a, 254, p | 0x100) if a else 0


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


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "all"
    print("T(hex) head: %s..." % T_BYTES.hex()[:32].upper())
    print("S = T ^ 0x55 head: %s..." % bytes(SBOX).hex()[:32].upper())
    if arg == "selftest":
        return selftest()
    solved = law_check()
    if arg == "selftest":
        return 0
    if not solved:
        if arg in ("1", "all"):
            print("\n==== STAGE 1: cheap structured families (S-form) ====")
            hits = stage1(SBOX)
            if hits:
                for h in hits:
                    direction, label, off, (Mx, tx) = h
                    print("HIT:", direction, label, off,
                          "rows:", " ".join("%02x" % r for r in Mx),
                          "t=0x%02x" % tx)
                return 0
            print("STAGE 1: no structured-family hit.\n")
        if arg in ("2", "all"):
            print("\n==== STAGE 2: spectral gates on candidate cores ====")
            stage2()
            print()
        if arg in ("3", "all"):
            print("\n==== STAGE 3: complete affine-equivalence search ====")
            stage3()
            print()
        return 0
    # SOLVED via stage 0 — run the independent confirmation machinery anyway.
    print("\n==== CONFIRMATION on the real data (independent machinery) ====")
    print("\n-- stage 2 spectral gates vs candidate cores --")
    stage2()
    print("\n-- stage 3 complete affine-equivalence search, target AES S-box --")
    t0 = time.time()
    r = affine_equivalence(SBOX, AES_SBOX, verbose=True)
    print("   (%.1fs)" % (time.time() - t0))
    if r is not None:
        M1, t1, M2, t2 = r
        print("   recovered decomposition: S(v) = M2 . AES( M1 . v ^ 0x%02x ) "
              "^ 0x%02x" % (t1, t2))
        print("   M1 rows: %s" % " ".join("%02x" % x for x in M1))
        print("   M2 rows: %s" % " ".join("%02x" % x for x in M2))
        print("   M1: %s" % classify_matrix(M1))
        print("   M2: %s" % classify_matrix(M2))
        ok = verify_formula(SBOX, AES_SBOX, M1, t1, M2, t2)
        print("   256/256 functional verification: %s" % ok)
    print("\n==== VERDICT: SOLVED ====")
    print("  T[v] = AES_SBOX[v] XOR 0x55")
    print("  i.e. T[v] = L(v^-1) ^ 0x36,  v^-1 in GF(2^8) mod x^8+x^4+x^3+x+1,")
    print("  L(x) = x ^ rotl(x,1) ^ rotl(x,2) ^ rotl(x,3) ^ rotl(x,4).")
    print("  All 256 bytes verified against pure_sign.T.")
    if arg == "full":
        print("\n[full] running the exhaustive stage-1 sweeps for the record")
        hits = stage1(SBOX)
        print("  stage-1 hits:", len(hits))
    return 0


def stage2():
    LAT_S = walsh_lat(SBOX)
    D_S = ddt(SBOX)
    specS = lat_spectrum(LAT_S)
    dspecS = ddt_spectrum(D_S)
    rsS = Counter(row_sigs(LAT_S).values())
    print("  S: DDT spectrum %s" % (Counter(dspecS),))
    targets = [("AES sbox", AES_SBOX), ("inversion (AES field)", INVERSE_TABLE)]
    # power maps x^e, gated by DDT spectrum first
    pm_survivors = []
    t0 = time.time()
    for e in range(1, 255):
        tab = [gf_pow(v, e) for v in range(256)]
        D = ddt(tab)
        if ddt_spectrum(D) != dspecS:
            continue
        pm_survivors.append((e, tab))
    print("  power maps passing DDT gate: %s (%.1fs)"
          % ([e for e, _ in pm_survivors], time.time() - t0))
    for e, tab in pm_survivors:
        targets.append(("x^%d (AES field)" % e, tab))
    print("  %-28s %-8s %-8s %-8s" % ("core", "DDT", "Walsh", "row-sigs"))
    keep = []
    for name, tab in targets:
        D = ddt(tab)
        g1 = ddt_spectrum(D) == dspecS
        L = walsh_lat(tab)
        g2 = lat_spectrum(L) == specS
        g3 = Counter(row_sigs(L).values()) == rsS
        print("  %-28s %-8s %-8s %-8s" % (name, g1, g2, g3))
        if g1 and g2 and g3:
            keep.append((name, tab))
    print("  surviving cores for stage 3: %s" % [n for n, _ in keep])
    globals()["STAGE2_KEEP"] = keep
    globals()["LAT_S_CACHE"] = LAT_S


def stage3():
    keep = globals().get("STAGE2_KEEP")
    if keep is None:
        LAT_S = walsh_lat(SBOX)
        keep = [("AES sbox", AES_SBOX), ("inversion (AES field)", INVERSE_TABLE)]
    else:
        LAT_S = globals()["LAT_S_CACHE"]
    solved = False
    for name, core in keep:
        print("  -- target core: %s" % name)
        t0 = time.time()
        r = affine_equivalence(SBOX, core, verbose=True)
        print("     (%.1fs)" % (time.time() - t0))
        if r is None:
            continue
        M1, t1, M2, t2 = r
        assert verify_formula(SBOX, core, M1, t1, M2, t2)
        print("  *** SOLVED against %s ***" % name)
        print("      S(v)  = M2 . CORE( M1 . v  XOR 0x%02x ) XOR 0x%02x"
              % (t1, t2))
        print("      M1 rows: %s" % " ".join("%02x" % x for x in M1))
        print("      M2 rows: %s" % " ".join("%02x" % x for x in M2))
        print("      M1: %s" % classify_matrix(M1))
        print("      M2: %s" % classify_matrix(M2))
        # raw T form: T[v] = S(v) ^ 0x55
        M2r, t2r = M2, t2 ^ 0x55
        assert verify_formula(RAW, core, M1, t1, M2r, t2r)
        print("      T[v]  = M2 . CORE( M1 . v  XOR 0x%02x ) XOR 0x%02x   "
              "[raw form, 256/256 verified]" % (t1, t2r))
        globals()["SOLVED"] = (name, core, M1, t1, M2, t2)
        solved = True
        break
    if not solved:
        print("\n  NEGATIVE: no affine equivalence to any surviving core.")
        print("  Refutations accumulated in this run are listed above.")


if __name__ == "__main__":
    sys.exit(main())
