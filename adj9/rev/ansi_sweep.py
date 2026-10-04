#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ansi_sweep.py - the stream nobody swept: bionic newrand (ANSI LCG, API 30+)
vs lrand48, against the pre-whitening region words and the fresh-3 bodies.

Prior art (l48_sweep.md / l48_pairs.py): lrand48 ONLY was ever swept, seeds
second-0..-600, 2M draws.  This sweep adds:

  stream A (newrand, task spec): srand(s) -> state = s (state 0 -> 1);
      rand(): state = (state*1103515245 + 12345) & 0x7FFFFFFF, return state
      (31-bit, returns the state AFTER the step).
  stream B (lrand48): X = (0x5DEECE66D*X + 0xB) mod 2^48, X0 = (s<<16)|0x330E,
      draw = X >> 17.  (Re-swept with the NEW seed ranges / depths:
      second-600..+600 and 3M draws vs the old -600..0 / 2M.)

Forms per draw stream r_k (k = 0-based draw index, first draw after srand = 0):
  single r_k
  pair   r_k ^ r_{k+1}            (overlapping; subsumes the proven
                                   non-overlap VM unit d[2j]^d[2j+1] = pair[2j])
  skip2  r_k ^ r_{k+2}
  triple r_k ^ r_{k+1} ^ r_{k+2}
  quad   r_k..r_{k+3}
  si-variants: form ^ si, si in {20, 8, 4, 2} - REGION rows only (the small
      ints the region builder pushes between units; fresh bodies are whitened
      VM output, tested pure + C only, matching l48_pairs pass D).
  C-family: single^C and pair^C, C in POOL32 (678 entries, the l48_pairs.py
      constant builder, reused verbatim via import).

Seeds:
  region rows (all_signings.json descriptors + pair_h3.json seconds via the
  l48_pairs.py content mapping): second-600..+600 step 1.  Rows sharing a
  second are swept together ({7,8,9} @1789240512, {2,4} @1789240075) - one
  srand per resume means one stream per second.  Note: corpus_seed.md's
  created_at seconds for rows 2/3 (1789239801) differ from pair_h3's
  (1789240075/76) by 274/275 s - inside the +-600 window, so covered either
  way (off_alt = off+274/275).
  fresh-3 (signings_extract.json, 44 body dwords BE+LE per signing):
  sec-600..+600 step 1 UNION sec-0..-3600 step 10, ALL THREE signings'
  words checked per seed (the single-resume shared-stream model is included
  by construction; seed = signing-1's sec appears in every row's window).

Method: per seed the whole 3M-draw stream is generated in numpy via the
affine form r_i = (a^(i+1)*s0 + b_{i+1}) mod M (P/Q power tables built once
per worker by squaring; mod-2^48 multiply via 16-bit splits - both verified
against pure-python reference generators in pass 0, plus the lrand48 anchor
W0=13271271 and the fresh make_header(sec) law).  All five forms are
concatenated into one ~15M-element array and membership-tested against a
2^28-bit Bloom bitmap of the union target set; bitmap hits are rechecked
EXACTLY per form against sorted target arrays and resolved to (word, C/si)
tags.  FP rate ~|union|/2^28 (~1e-4) - the exact recheck removes them, so
the method is exact (no false negatives: every target value is in the
bitmap).

Outputs: ansi_sweep.log (pass 0 + progress + hit/flag tables + analysis),
ansi_sweep_hits.csv (EVERY hit incl. C-family).
"""
import json
import os
import sys
import time
from collections import defaultdict

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import l48_pairs as L48          # POOL32, ROWS, SECOND, TS, CT (reused verbatim)
from header_gen import make_header

# ------------------------------------------------------------------ constants
M31 = (1 << 31) - 1
M48 = (1 << 48) - 1
A_A, C_A = 1103515245, 12345             # stream A: bionic newrand ANSI LCG
A_B, C_B = 0x5DEECE66D, 0xB              # stream B: lrand48
SI = (20, 8, 4, 2)                       # ints pushed between units (0x14?,4,8,2)
FORMS = ("single", "pair", "skip2", "triple", "quad")
# concat layout [single | pair | skip2 | triple | quad]; lens K,K-1,K-2,K-2,K-3

LOG_PATH = os.path.join(HERE, "ansi_sweep.log")
CSV_PATH = os.path.join(HERE, "ansi_sweep_hits.csv")
LOGF = None
K = 3_000_000
KOFF = None


def set_K(k):
    global K, KOFF
    K = k
    KOFF = np.array([0, k, 2 * k - 1, 3 * k - 3, 4 * k - 5], dtype=np.int64)


def log(m=""):
    print(m, flush=True)
    if LOGF is not None:
        LOGF.write(m + "\n")


# ------------------------------------------------------------- fresh corpus
FRESH_PATH = os.path.join(os.path.dirname(HERE), "device", "java_dump",
                          "signings_extract.json")
FRESH_RAW = json.load(open(FRESH_PATH, encoding="utf-8"))["signings"]
FSEC = {100: 1790106110, 101: 1790106176, 102: 1790106196}   # header-inverted
FRESH_ROWID = {100 + s["n"] - 1: s for s in FRESH_RAW}
ALT_SEC = {2: 1789239801, 3: 1789239801}   # corpus_seed.md created_at secs


def _fresh_words(s):
    body = bytes.fromhex(s["blob"])[16:]
    out = {}
    for j in range(len(body) // 4):
        wbe = int.from_bytes(body[4 * j:4 * j + 4], "big")
        wle = int.from_bytes(body[4 * j:4 * j + 4], "little")
        out[wbe] = "n%ddw%d" % (s["n"], j)
        if wle != wbe:
            out.setdefault(wle, "n%ddw%dLE" % (s["n"], j))
    return out


FRESH_NAMES = {rid: _fresh_words(s) for rid, s in FRESH_ROWID.items()}


class _FR(object):
    pass


FRESH_CT = {}
for _rid, _nm in FRESH_NAMES.items():
    _o = _FR()
    _o.names = _nm
    FRESH_CT[_rid] = L48.c_targets(_o)

ROW_NAMES = {i: L48.ROWS[i].names for i in range(10)}
ROW_NAMES.update(FRESH_NAMES)
ROW_SEC = {i: L48.SECOND[i] for i in range(10)}
ROW_SEC.update(FSEC)
ROW_LABEL = {i: "row%d(%s)" % (i, L48.SRC.get(i, "?")) for i in range(10)}
ROW_LABEL.update({rid: "fresh%d" % (rid - 99) for rid in FSEC})
ROW_SEC_ARR = np.array([ROW_SEC[r] for r in range(103)], dtype=np.int64)


def row_ct(rid):
    return L48.CT[rid] if rid < 100 else FRESH_CT[rid]


def row_pxable(rid):
    return [v for v in ROW_NAMES[rid] if not (v >> 31)]


def ts_of(rid):
    return L48.TS[rid] if rid < 100 else FRESH_ROWID[rid]["ts"]


# ------------------------------------------------------------------ streams
def build_powers_A(n):
    """PA[j] = A^(j+1) mod 2^31, QA[j] = b_(j+1) mod 2^31 (b_0=0)."""
    m0 = 1024
    P = np.empty(m0, dtype=np.uint64)
    Q = np.empty(m0, dtype=np.uint64)
    p, b = A_A, 0
    for j in range(m0):
        P[j] = p
        b = (b * A_A + C_A) & M31
        Q[j] = b
        p = (p * A_A) & M31
    while P.shape[0] < n:
        an = int(P[-1])                       # a^Ln
        bn = int(Q[-1])                       # b_Ln
        P2 = (P * np.uint64(an)) & np.uint64(M31)
        Q2 = (P * np.uint64(bn) + Q) & np.uint64(M31)
        P = np.concatenate([P, P2])
        Q = np.concatenate([Q, Q2])
    return P[:n].copy(), Q[:n].copy()


def _mul48(P, Ph, Pl, s):
    """(P * s) mod 2^48 for uint64 array P (<2^48) and python-int s (<2^48),
    via 16-bit splits (all intermediates < 2^64)."""
    sH = np.uint64(s >> 16)
    sL = np.uint64(s & 0xFFFF)
    t = Ph * sH
    t &= np.uint64(0xFFFF)
    t <<= np.uint64(16)
    t += Pl * sH
    t &= np.uint64(0xFFFFFFFF)
    t <<= np.uint64(16)
    t += P * sL
    t &= np.uint64(M48)
    return t


def build_powers_B(n):
    """PB[j] = a^(j+1) mod 2^48, QB[j] = b_(j+1) mod 2^48."""
    m0 = 1024
    P = np.empty(m0, dtype=np.uint64)
    Q = np.empty(m0, dtype=np.uint64)
    p, b = A_B, 0
    for j in range(m0):
        P[j] = p
        b = (b * A_B + C_B) & M48
        Q[j] = b
        p = (p * A_B) & M48
    while P.shape[0] < n:
        an = int(P[-1])
        bn = int(Q[-1])
        Ph = P >> np.uint64(16)
        Pl = P & np.uint64(0xFFFF)
        P2 = _mul48(P, Ph, Pl, an)
        Q2 = _mul48(P, Ph, Pl, bn)
        Q2 += Q
        Q2 &= np.uint64(M48)
        P = np.concatenate([P, P2])
        Q = np.concatenate([Q, Q2])
    P = P[:n].copy()
    Q = Q[:n].copy()
    return P, Q, P >> np.uint64(16), P & np.uint64(0xFFFF)


def genA(seed):
    """first K newrand draws after srand(seed) as uint32 array."""
    s0 = seed & 0xFFFFFFFF
    if s0 == 0:
        s0 = 1
    t = PA * np.uint64(s0)
    t += QA
    t &= np.uint64(M31)
    return t.astype(np.uint32)


def genB(seed):
    """first K lrand48 draws after srand48(seed) as uint32 array."""
    x0 = (((seed & 0xFFFFFFFF) << 16) + 0x330E) & M48
    t = _mul48(PB, PBh, PBl, x0)
    t += QB
    t &= np.uint64(M48)
    return (t >> np.uint64(17)).astype(np.uint32)


def refA(seed, n):
    st = seed & 0xFFFFFFFF
    if st == 0:
        st = 1
    out = []
    for _ in range(n):
        st = (st * A_A + C_A) & M31
        out.append(st)
    return out


def refB(seed, n):
    x = ((seed << 16) + 0x330E) & M48
    out = []
    for _ in range(n):
        x = (A_B * x + C_B) & M48
        out.append(x >> 17)
    return out


def forms_cat(r):
    """concat [single|pair|skip2|triple|quad] of draw array r (uint32)."""
    pair = r[:-1] ^ r[1:]
    skip2 = r[:-2] ^ r[2:]
    tri = r[:-2] ^ r[1:-1]
    tri ^= r[2:]
    qu = r[:-3] ^ r[1:-2]
    qu ^= r[2:-1]
    qu ^= r[3:]
    return np.concatenate([r, pair, skip2, tri, qu])


# ------------------------------------------------------------------ groups
GC = {}          # group cache (worker): gid -> dict
BITLUT = np.array([1 << j for j in range(8)], dtype=np.uint8)


def build_group(gid):
    rows = gid[2]
    region = gid[0] == "R"
    px = set()
    ct_vals = set()
    for rid in rows:
        px.update(row_pxable(rid))
        ct_vals.update(int(x) for x in row_ct(rid)[0].tolist())
    # si-variants model the small ints the REGION builder pushes between
    # units (0x14/8/4/2); fresh bodies are VM output - pure + C only there.
    si = set()
    if region:
        for w in px:
            for s in SI:
                si.add(w ^ s)
    base = sorted(px | si)
    T0 = np.array(sorted(set(base) | ct_vals), dtype=np.uint32)
    Tb = np.array(base, dtype=np.uint32)
    T = [T0, T0, Tb, Tb, Tb]
    TAGS = [dict() for _ in range(5)]
    for rid in rows:
        for v in ROW_NAMES[rid]:
            if not (v >> 31):
                for f in range(5):
                    TAGS[f].setdefault(v, []).append((rid, 0, 0))
                    if region:
                        for s in SI:
                            TAGS[f].setdefault(v ^ s, []).append((rid, 1, s))
        tg = row_ct(rid)[1]
        for f in (0, 1):
            d = TAGS[f]
            for v, lst in tg.items():
                for (_nm, c) in lst:
                    d.setdefault(v, []).append((rid, 2, c))
    bm = np.zeros(1 << 25, dtype=np.uint8)   # 2^28 bits, indexed by low 28 bits
    union = np.array(sorted(px | si | ct_vals), dtype=np.uint32)
    lo28 = (union & np.uint32(0x0FFFFFFF)) >> 3
    np.bitwise_or.at(bm, lo28.astype(np.int64), BITLUT[union & 7])
    return {"bm": bm, "T": T, "TAGS": TAGS, "rows": rows}


def get_group(gid):
    g = GC.get(gid)
    if g is None:
        if len(GC) >= 2:
            GC.pop(next(iter(GC)))
        g = GC[gid] = build_group(gid)
    return g


def do_job(job):
    gid, seed = job
    G = get_group(gid)
    out = []
    for st, gen in ((0, genA), (1, genB)):
        r = gen(seed)
        cat = forms_cat(r)
        del r
        idx = (cat & np.uint32(0x0FFFFFFF)) >> np.uint32(3)
        gth = G["bm"][idx]
        del idx
        hit = np.nonzero(gth & BITLUT[cat & np.uint32(7)])[0]
        del gth
        if hit.size:
            starts = KOFF
            fid = np.searchsorted(starts, hit, side="right") - 1
            kk = hit - starts[fid]
            vals = cat[hit]
            for f in range(5):
                sel = np.nonzero(fid == f)[0]
                if not sel.size:
                    continue
                v = vals[sel]
                k2 = kk[sel]
                T = G["T"][f]
                pos = np.searchsorted(T, v)
                np.clip(pos, 0, T.shape[0] - 1, out=pos)
                eq = T[pos] == v
                for j in np.nonzero(eq)[0]:
                    val = int(v[j])
                    kx = int(k2[j])
                    for (rid, kind, arg) in G["TAGS"][f].get(val, ()):
                        out.append((rid, st, seed, f, kx, kind, arg, val))
        del cat, hit
    return out


def _winit(k):
    global PA, QA, PB, QB, PBh, PBl
    set_K(k)
    PA, QA = build_powers_A(K)
    PB, QB, PBh, PBl = build_powers_B(K)


# -------------------------------------------------------------------- jobs
def build_jobs(offrange, fresh_deep):
    g = defaultdict(list)
    for i in range(10):
        g[L48.SECOND[i]].append(i)
    jobs = []
    meta = []
    for sec in sorted(g):
        rows = tuple(sorted(g[sec]))
        gid = ("R", sec, rows)
        meta.append((gid, len(list(offrange))))
        for off in offrange:
            jobs.append((gid, sec + off))
    fseed = set()
    for sec in FSEC.values():
        fseed.update(sec + o for o in offrange)
        fseed.update(sec - m for m in fresh_deep)
    gid = ("F", 0, tuple(sorted(FSEC)))
    meta.append((gid, len(fseed)))
    for s in sorted(fseed):
        jobs.append((gid, s))
    return jobs, meta


def resolve_words(rid, kind, arg, val):
    nm = ROW_NAMES[rid]
    if kind == 0:
        return nm.get(val, "?")
    if kind == 1:
        return nm.get(val ^ arg, "?")
    tg = row_ct(rid)[1]
    lst = tg.get(val, [])
    return "|".join("%s^C%08x" % (w, c) for (w, c) in lst if c == arg) or "?"


# ------------------------------------------------------------------ pass 0
def pass0():
    log("=" * 78)
    log("PASS 0 - self tests")
    log("=" * 78)
    log("POOL32 entries: %d (l48_pairs builder, reused verbatim)" % len(L48.POOL32))
    ok = True
    for s in (1789240512, 1790106110, 987654321, 123456789):
        ra = refA(s, 500)
        rb = refB(s, 500)
        ga = genA(s)[:500]
        gb = genB(s)[:500]
        ma = [int(x) for x in ga] == ra
        mb = [int(x) for x in gb] == rb
        ok = ok and ma and mb
        log("  seed %d: genA==refA %s ; genB==refB %s" % (s, ma, mb))
    rB = genB(1789240512)
    a = int(rB[214220]) ^ int(rB[214221])
    log("  anchor: lrand48(1789240512) d[214220]^d[214221] = %08x "
        "(row7 W0=13271271) match=%s" % (a, a == 0x13271271))
    ok = ok and a == 0x13271271
    for rid, s in sorted(FRESH_ROWID.items()):
        blob = bytes.fromhex(s["blob"])
        h = make_header(FSEC[rid]).hex()
        log("  fresh n=%d: make_header(%d)=%s.. blob[0:16]=%s.. match=%s"
            % (s["n"], FSEC[rid], h, blob[:16].hex(), h == blob[:16].hex()))
        ok = ok and h == blob[:16].hex()
    for i in range(10):
        log("  row %d sec=%d pxable=%d ct=%d alt_sec=%s"
            % (i, L48.SECOND[i], len(row_pxable(i)), len(row_ct(i)[0]),
               ALT_SEC.get(i)))
    for rid in sorted(FSEC):
        log("  %s sec=%d words=%d pxable=%d ct=%d"
            % (ROW_LABEL[rid], FSEC[rid], len(ROW_NAMES[rid]),
               len(row_pxable(rid)), len(row_ct(rid)[0])))
    log("  SELF TESTS: %s" % ("OK" if ok else "FAILED"))
    return ok


# ---------------------------------------------------------------- analysis
def analyze(pure_evs, carr, offrange, fresh_deep, T0):
    log("")
    log("=" * 78)
    log("ANALYSIS")
    log("=" * 78)
    njobs_reg = len(list(offrange))
    fseed = set()
    for sec in FSEC.values():
        fseed.update(sec + o for o in offrange)
        fseed.update(sec - m for m in fresh_deep)
    njobs_fr = len(fseed)
    POS = 5.0 * K - 8          # pure/si positions per stream (5 forms)
    POSC = 2.0 * K - 1         # C positions per stream (single + pair)

    # exact expectations
    E = {}
    NT = {}
    for rid in list(range(10)) + sorted(FSEC):
        px = set(row_pxable(rid))
        nt = len(px | {w ^ s for w in px for s in SI}) if rid < 100 else len(px)
        nj = njobs_fr if rid >= 100 else njobs_reg
        e_p = nt * POS / float(1 << 31) * nj
        e_c = len(row_ct(rid)[0]) * POSC / float(1 << 31) * nj
        NT[rid] = nt
        E[rid] = (e_p, e_c)
        log("  %-22s nt_pure=%4d E_pure=%7.1f |  |CT|=%5d E_c=%8.1f"
            % (ROW_LABEL[rid], nt, e_p, len(row_ct(rid)[0]), e_c))
    tp = sum(E[r][0] for r in E)
    tc = sum(E[r][1] for r in E)
    log("  TOTAL                     E_pure=%7.1f          E_c=%8.1f"
        % (tp, tc))
    lam_p = {r: E[r][0] / (njobs_fr if r >= 100 else njobs_reg) / 2.0 for r in E}
    lam_c = {r: E[r][1] / (njobs_fr if r >= 100 else njobs_reg) / 2.0 for r in E}

    # ---- pure/si events (dedup by rid,st,seed,f,k,val)
    ded = {}
    for (rid, st, seed, f, k, arg, val) in pure_evs:
        key = (rid, st, seed, f, k, val)
        if key not in ded:
            ded[key] = arg
    events = [(rid, st, seed, seed - ROW_SEC[rid], f, k, arg, val)
              for (rid, st, seed, f, k, val), arg in ded.items()]
    npure = len(events)
    log("")
    log("pure/si events (dedup): %d   [expected %.1f]   %s"
        % (npure, tp, "ON CHANCE LINE" if abs(npure - tp) < 3 * tp ** 0.5 + 5
           else "*** OFF the chance line ***"))

    # ---- per-cell pure structure   (event tuple: rid,st,seed,off,f,k,arg,val)
    cells = defaultdict(list)
    for ev in events:
        cells[(ev[0], ev[1], ev[3])].append(ev)
    flagA, flagB, superB = [], [], []
    for (rid, st, off), hh in cells.items():
        ks = sorted(e[5] for e in hh)
        span = ks[-1] - ks[0]
        n = len(hh)
        if n >= 2 and span <= 2000:
            flagA.append((rid, st, off, hh, span))
        if n >= 3 and span <= 20000:
            flagB.append((rid, st, off, hh, span))
        if n >= 4 and span <= 2000:
            superB.append((rid, st, off, hh, span))
    expA = sum((njobs_fr if r >= 100 else njobs_reg) * 2 * 0.5 * lam_p[r] ** 2
               * (2 * 2000.0 / K) for r in E)
    expB = sum((njobs_fr if r >= 100 else njobs_reg) * 2
               * (lam_p[r] ** 3 / 6.0) * (2 * 20000.0 / K) for r in E)
    exp4 = sum((njobs_fr if r >= 100 else njobs_reg) * 2
               * (lam_p[r] ** 4 / 24.0) * (2 * 2000.0 / K) for r in E)
    log("")
    log("-- pure cells: >=2 hits span<=2000: %d (chance %.2f) ; >=3 span<=20000:"
        " %d (chance %.2f) ; >=4 span<=2000: %d (chance %.2f) --"
        % (len(flagA), expA, len(flagB), expB, len(superB), exp4))
    for (rid, st, off, hh, span) in sorted(flagA):
        log("  FLAG-A %s stream=%s off=%+d n=%d span=%d: %s"
            % (ROW_LABEL[rid], "AB"[st], off, len(hh), span,
               ["%s k=%d" % (ROW_NAMES[rid].get(e[7] ^ e[6], "%08x" % e[7]),
                             e[5])
                for e in sorted(hh, key=lambda x: x[5])]))
    for (rid, st, off, hh, span) in sorted(flagB):
        log("  FLAG-B %s stream=%s off=%+d n=%d span=%d: %s"
            % (ROW_LABEL[rid], "AB"[st], off, len(hh), span,
               ["%s k=%d" % (ROW_NAMES[rid].get(e[7] ^ e[6], "%08x" % e[7]),
                             e[5])
                for e in sorted(hh, key=lambda x: x[5])]))
    for (rid, st, off, hh, span) in sorted(superB):
        log("  SUPER-B %s stream=%s off=%+d n=%d span=%d (chance %.2f)"
            % (ROW_LABEL[rid], "AB"[st], off, len(hh), span, exp4))

    # ---- same-seed multi-row (region same-second groups + fresh trio)
    byseed = defaultdict(lambda: defaultdict(list))
    for ev in events:
        byseed[(ev[1], ev[2])][ev[0]].append(ev)
    x2 = x3 = 0
    for (st, seed), rm in sorted(byseed.items()):
        if len(rm) < 2:
            continue
        ks_all = [e[5] for evs in rm.values() for e in evs]
        span = max(ks_all) - min(ks_all)
        rws = sorted(rm, key=ts_of)
        if span <= 2000:
            x2 += 1
            ks = {r: sorted(e[5] for e in rm[r]) for r in rws}
            ordered = all(max(ks[rws[i]]) < min(ks[rws[i + 1]])
                          for i in range(len(rws) - 1))
            log("  XROW-2K stream=%s seed=%d (offs %s) rows=%s ordered=%s "
                "span=%d gaps=%s k=%s"
                % ("AB"[st], seed,
                   {ROW_LABEL[r]: seed - ROW_SEC[r] for r in rws},
                   [ROW_LABEL[r] for r in rws], ordered, span,
                   [min(ks[rws[i + 1]]) - max(ks[rws[i]])
                   for i in range(len(rws) - 1)],
                   {ROW_LABEL[r]: ks[r][:8] for r in rws}))
        elif len(rm) >= 3 and span <= 20000:
            x3 += 1
            log("  XROW-3W stream=%s seed=%d rows=%s span=%d (weak)"
                % ("AB"[st], seed, [ROW_LABEL[r] for r in rws], span))
    expX = 0.0
    for gid_rows, nj in (((7, 8, 9), njobs_reg), ((2, 4), njobs_reg),
                         ((100, 101, 102), njobs_fr)):
        lam = sum(lam_p[r] for r in gid_rows)
        n = len(gid_rows)
        pm = lam * (2 * 2000.0 / K)          # P(row has a hit in the window)
        e = nj * 2 * sum(comb(n, m) * pm ** m * (1 - pm) ** (n - m)
                         for m in (2, 3))
        expX += e
    log("  same-seed multi-row pure groups span<=2000: %d (chance ~%.3f) ; "
        ">=3 rows span<=20000: %d" % (x2, expX, x3))

    # ---- C-family
    log("")
    if carr is not None and carr.shape[0]:
        c2 = carr[carr[:, 5] != 0]           # drop C=0 twins of pure hits
        nc = c2.shape[0]
        log("C-family tag-lines (C!=0): %d   [expected %.1f]   %s"
            % (nc, tc, "ON CHANCE LINE" if abs(nc - tc) < 3 * tc ** 0.5 + 5
               else "*** OFF the chance line ***"))
        offs = c2[:, 2] - ROW_SEC_ARR[c2[:, 0]]
        ckey = (c2[:, 0] * 8 + c2[:, 1]) * 200000 + (offs + 100000)
        uk, cnt = np.unique(ckey, return_counts=True)
        mx = int(cnt.max())
        mxi = int(uk[cnt.argmax()])
        mridst, moff = divmod(mxi, 200000)
        mrid, mst = divmod(mridst, 8)
        log("  C cells: %d ; max hits in one cell: %d (%s stream=%s off=%+d, "
            "noise line %.0f)"
            % (uk.shape[0], mx, ROW_LABEL[mrid], "AB"[mst], moff - 100000,
               lam_c[mrid] + 8 * lam_c[mrid] ** 0.5))
        thresh = {r: max(3.0, lam_c[r] + 8 * lam_c[r] ** 0.5) for r in E}
        flagged = [(int(k), int(c)) for k, c in zip(uk, cnt)
                   if c >= thresh[(k // 200000) // 8]]
        log("  FLAG-C cells (count >= noise line %.0f/%.0f): %d"
            % (thresh[7], thresh[100], len(flagged)))
        if flagged:
            keys = np.array([k for k, _ in flagged], dtype=np.int64)
            selmask = np.isin(ckey, keys)
            for row in c2[selmask][:80]:
                rid, st, seed, f, k, arg, val = [int(x) for x in row]
                log("    FLAG-C %s stream=%s off=%+d %s k=%d C=%08x val=%08x"
                    % (ROW_LABEL[rid], "AB"[st], seed - ROW_SEC[rid],
                       FORMS[f], k, arg, val))
        # same (word,C) tag across different rows, tight in k
        order = np.lexsort((c2[:, 2], c2[:, 1], c2[:, 6], c2[:, 5]))
        cs = c2[order]
        if cs.shape[0] > 1:
            eqr = (cs[1:, 5] == cs[:-1, 5]) & (cs[1:, 6] == cs[:-1, 6])
            bnd = np.flatnonzero(~eqr) + 1
            startsR = np.concatenate([[0], bnd])
            endsR = np.concatenate([bnd, [cs.shape[0]]])
            ntags = 0
            for b, e in zip(startsR.tolist(), endsR.tolist()):
                if e - b < 2:
                    continue
                rids = np.unique(cs[b:e, 0])
                if rids.size < 2:
                    continue
                ntags += 1
                if ntags <= 60:
                    offl = cs[b:e, 2] - ROW_SEC_ARR[cs[b:e, 0]]
                    log("    TAG-X val=%08x C=%08x rows=%s offs=%s k=%s"
                        % (int(cs[b, 6]), int(cs[b, 5]),
                           [ROW_LABEL[int(x)] for x in rids],
                           sorted(set(int(o) for o in offl)),
                           [int(x) for x in cs[b:e, 4]]))
            log("  tags hitting >=2 distinct rows: %d (structurally-shared "
                "small values expected; a REAL repeat = same off + tight k)"
                % ntags)
    else:
        log("C-family: no hits")

    # ---- distributions
    fc = defaultdict(int)
    for ev in events:
        fc[(ev[1], FORMS[ev[4]])] += 1
    log("")
    log("-- pure/si events by (stream, form) --")
    for st in (0, 1):
        log("  stream %s: %s" % ("AB"[st], {fm: fc[(st, fm)] for fm in FORMS}))
    log("")
    log("-- fresh-3 focus (pure/si) --")
    for rid in sorted(FSEC):
        for st in (0, 1):
            h = [e for e in events if e[0] == rid and e[1] == st]
            near = [e for e in h if abs(e[3]) <= 10]
            log("  %s stream=%s: pure=%d, |off|<=10: %d, min|off|=%d"
                % (ROW_LABEL[rid], "AB"[st], len(h), len(near),
                   min((abs(e[3]) for e in h), default=-1)))
    log("")
    log("total wall %.1f s" % (time.time() - T0))


def cells_k(cells):
    return cells


def comb(n, k):
    from math import factorial
    return factorial(n) // (factorial(k) * factorial(n - k))


# -------------------------------------------------------------------- main
if __name__ == "__main__":
    smoke = "--smoke" in sys.argv
    set_K(300_000 if smoke else 3_000_000)
    global PA, QA, PB, QB, PBh, PBl
    PA, QA = build_powers_A(K)
    PB, QB, PBh, PBl = build_powers_B(K)
    LOGF = open(LOG_PATH, "w", encoding="utf-8", buffering=1)
    T0 = time.time()
    log("=" * 78)
    log("ansi_sweep - stream A (bionic newrand ANSI LCG) vs stream B (lrand48)")
    log("start %s   K=%d draws/seed   smoke=%s" %
        (time.strftime("%Y-%m-%dT%H:%M:%S"), K, smoke))
    log("=" * 78)
    log("model A: srand(s)->state=s(0->1); rand: state=(state*1103515245+12345)"
        "&0x7FFFFFFF, return state")
    log("model B: srand48(s); X=(0x5DEECE66D*X+0xB) mod 2^48, draw=X>>17")
    log("forms: single, pair r_k^r_{k+1}, skip2 r_k^r_{k+2}, triple, quad; "
        "si-variants REGION rows only (form^si, si in %s); C-family "
        "single^C + pair^C, C in POOL32(%d)" % (list(SI), len(L48.POOL32)))
    log("seeds: region rows second-600..+600; fresh-3 sec-600..+600 union "
        "sec-0..-3600@10; rows sharing a second swept together")
    if not pass0():
        log("SELF TESTS FAILED - aborting")
        LOGF.close()
        sys.exit(1)

    offrange = range(-5, 6) if smoke else range(-600, 601)
    fresh_deep = range(0, 101, 10) if smoke else range(0, 3601, 10)
    jobs, meta = build_jobs(offrange, fresh_deep)
    log("")
    log("jobs: %d (region groups+seeds: %s ; fresh seeds: %d)"
        % (len(jobs), [(gid[1], gid[2], n) for (gid, n) in meta
                       if gid[0] == "R"], meta[-1][1]))

    import multiprocessing as mp
    nw = 4 if smoke else min(12, os.cpu_count() or 2)
    log("workers: %d" % nw)
    csvf = open(CSV_PATH, "w", encoding="utf-8", newline="")
    csvf.write("rowid,label,stream,seed,off,form,k,kind,arg,val,words\n")
    pure_evs = []
    cparts = []
    carr = None
    ndet = 0
    t0 = time.time()
    try:
        with mp.Pool(nw, initializer=_winit, initargs=(K,)) as pool:
            for done, hits in enumerate(pool.imap_unordered(do_job, jobs,
                                                            chunksize=4),
                                        1):
                jc = []
                for (rid, st, seed, f, k, kind, arg, val) in hits:
                    off = seed - ROW_SEC[rid]
                    csvf.write("%d,%s,%s,%d,%+d,%s,%d,%s,%d,%d,%s\n"
                               % (rid, ROW_LABEL[rid], "AB"[st], seed, off,
                                  FORMS[f], k,
                                  ("pure", "si", "C")[kind], arg, val,
                                  resolve_words(rid, kind, arg, val)))
                    if kind < 2:
                        pure_evs.append((rid, st, seed, f, k, arg, val))
                    else:
                        jc.append((rid, st, seed, f, k, arg, val))
                if jc:
                    cparts.append(np.array(jc, dtype=np.int64))
                ndet += len(hits)
                if done % 250 == 0 or done == len(jobs):
                    el = time.time() - t0
                    log("  %d/%d jobs (%.1fs, %.0f ms/job, eta %.1f min, "
                        "hits %d)" % (done, len(jobs), el, 1000.0 * el / done,
                                      (len(jobs) - done) * el / done / 60.0,
                                      ndet))
    except Exception as e:
        log("mp failed (%s) - single process fallback" % e)
        _winit(K)
        for job in jobs:
            jc = []
            for (rid, st, seed, f, k, kind, arg, val) in do_job(job):
                off = seed - ROW_SEC[rid]
                csvf.write("%d,%s,%s,%d,%+d,%s,%d,%s,%d,%d,%s\n"
                           % (rid, ROW_LABEL[rid], "AB"[st], seed, off,
                              FORMS[f], k, ("pure", "si", "C")[kind], arg,
                              val, resolve_words(rid, kind, arg, val)))
                if kind < 2:
                    pure_evs.append((rid, st, seed, f, k, arg, val))
                else:
                    jc.append((rid, st, seed, f, k, arg, val))
            if jc:
                cparts.append(np.array(jc, dtype=np.int64))
    if cparts:
        carr = np.vstack(cparts)
    csvf.close()
    log("sweep done: %d tag-hits (pure/si %d, C %d), %.1fs"
        % (ndet, len(pure_evs), 0 if carr is None else carr.shape[0],
           time.time() - t0))
    analyze(pure_evs, carr, offrange, fresh_deep, T0)
    log("=" * 78)
    LOGF.close()
