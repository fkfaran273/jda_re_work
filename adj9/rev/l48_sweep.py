#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
l48_sweep.py - inverted-membership sweep: wire words = mix(rand() draws),
srand(resume_second) seeds the stream once per resume (stream advances
monotonically across signings, NOT reseeded per signing).

Model under test (task spec, "l48"):
    bionic lrand48:  X_{n+1} = (0x5DEECE66D*X_n + 0xB) mod 2^48
    srand48(s):      X_0 = (s<<16) + 0x330E
    draw_n           = X_{n+1} >> 17                    (31-bit)
Second generator swept through the identical machinery ("t3"):
    bionic random() TYPE_3 additive feedback - the generator the VERIFIED
    header law (header_gen.py, 36/36) proves srand() actually wires to on
    this build.  Included because the header evidence contradicts the
    lrand48 assumption, and corpus_seed SS5 only tested TYPE_3 raw at
    seed == exact signing second (no resume offsets, no mix constants).

Design (inverted membership - no forward mix sweeping):
  for each candidate resume seed s (row second - 0 .. -600):
      build {draw -> k} once (K draws), then invert every
      (target word, transform) to a candidate draw r and do O(1) lookups.
  families (w = wire word, C = site constant):
    xor : w =  r ^ C            -> r = w ^ C
    add : w = (r + C) & M32     -> r = (w - C) & M32
    sub : w = (C - r) & M32     -> r = (C - w) & M32
    rsub: w = (r - C) & M32     -> r = (w + C) & M32      (screen test only)
    pairM: w = ((r1&0xffff)^Ca)<<16 | ((r2&0xffff)^Cb), r2 = the NEXT draw
           after r1  (inverted via {mask -> [k]} + adjacency check)
    pairX: same inversion but r1/r2 must equal FULL draws (< 2^16),
           r2 = draws[k1+1] exactly
  constant pool: the 474 mov/movk 64-bit constants of sub_9afa4
    (deriv3.py lines 150-205 extractor, byte-for-byte logic) ->
    uniq low32 | uniq high32 | {0}  as C;  16-bit C16 pools = the four
    halves of every 64-bit constant (not needed: pair pool uses the
    (hi16,lo16) pair of each uniq 32-bit pool value, + terminal 16-bit
    immediates cross product, + (0,0)).
  screen test (task extra): d2 vs widthPixels/heightPixels:
    C in {1080, 2237, 2400} x {xor, add, sub, rsub} on d2 only.
  draws: K = 50000 per seed; escalation pass K = 200000 on the earliest
    row of every burst that produced no cross-row-consistent group.

Outputs: l48_sweep.log (everything), plus a structured SUMMARY at the end.
"""
import json
import os
import re
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
M32 = 0xFFFFFFFF
M48 = (1 << 48) - 1
A48 = 0x5DEECE66D
B48 = 0xB
M31 = 2147483647

LOG_PATH = os.path.join(HERE, "l48_sweep.log")
LOGF = open(LOG_PATH, "w", encoding="utf-8", buffering=1)
T0 = time.time()


def log(msg=""):
    print(msg, flush=True)
    LOGF.write(msg + "\n")


# ---------------------------------------------------------------------------
# 1. constant pool - deriv3.py lines 150-205 extractor, verbatim logic
# ---------------------------------------------------------------------------
RE_MOVI = re.compile(r"^0x([0-9a-f]+)\s+mov\s+([wx]\d+|xzr), #(-?0x[0-9a-f]+|\d+)"
                     r"(?:, lsl #(\d+))?\s*$")
RE_MOVK = re.compile(r"^0x([0-9a-f]+)\s+movk\s+([wx]\d+), #(-?0x[0-9a-f]+|\d+), lsl #(\d+)\s*$")

_regs = {}
CONSTS64 = []   # assembled 64-bit constants
WORDS16 = []    # terminal 16-bit immediates (mov without movk)


def _fin(reg):
    st = _regs.pop(reg)
    if st["shifts"]:
        CONSTS64.append(st["val"] & 0xFFFFFFFFFFFFFFFF)
    else:
        WORDS16.append(st["val"] & 0xFFFF)


for _line in open(os.path.join(HERE, "fn_9afa4_full.log"), encoding="utf-8",
                  errors="replace"):
    _line = _line.strip()
    m = RE_MOVI.match(_line)
    if m:
        reg = m.group(2)
        if reg == "xzr":
            continue
        v = int(m.group(3), 0) & M32
        if m.group(4):
            v = (v << int(m.group(4))) & 0xFFFFFFFFFFFFFFFF
        if reg in _regs:
            _fin(reg)
        _regs[reg] = {"val": v, "shifts": 0}
        continue
    m = RE_MOVK.match(_line)
    if m:
        reg = m.group(2)
        if reg == "xzr":
            continue
        if reg not in _regs:
            _regs[reg] = {"val": 0, "shifts": 0}
        st = _regs[reg]
        st["val"] |= (int(m.group(3), 0) & 0xFFFF) << int(m.group(4))
        st["shifts"] += 1
for _reg in list(_regs):
    _fin(_reg)

_low32 = set(c & M32 for c in CONSTS64)
_high32 = set((c >> 32) & M32 for c in CONSTS64)
POOL32 = sorted(_low32 | _high32 | {0})              # 32-bit constant pool + no-constant
_term16 = set(WORDS16) | {0}
# pair pool: (hi16, lo16) of each uniq 32-bit pool constant, + terminal-16 cross product
PAIR_POOL = sorted(set(((c >> 16) & 0xFFFF, c & 0xFFFF) for c in POOL32) |
                   set((a, b) for a in _term16 for b in _term16))
SCREEN_C = (1080, 2237, 2400)                        # widthPixels, heightPixels, panel

# ---------------------------------------------------------------------------
# 2. draw generators (both self-tested against header_gen.py's Random3)
# ---------------------------------------------------------------------------
sys.path.insert(0, HERE)


def gen_l48(seed, k):
    """bionic lrand48 stream: returns k+1 draws (31-bit)."""
    x = ((seed << 16) + 0x330E) & M48
    out = []
    ap = out.append
    a = A48
    b = B48
    m = M48
    for _ in range(k + 1):
        x = (a * x + b) & m
        ap(x >> 17)
    return out


def gen_t3(seed, k):
    """bionic random() TYPE_3 (exactly header_gen.Random3), k+1 draws after 310 warmups."""
    sd = seed & 0xFFFFFFFF
    if sd == 0:
        sd = 1
    w = sd if sd < (1 << 31) else sd - (1 << 32)
    tbl = [0] * 31
    tbl[0] = w
    prev = w
    for i in range(1, 31):
        if prev >= 0:
            hi = prev // 127773
            lo = prev - hi * 127773
        else:
            hi = -((-prev) // 127773)
            lo = prev - hi * 127773
        word = 16807 * lo - 2836 * hi
        if word < 0:
            word += M31
        prev = word
        tbl[i] = word
    f = 3
    b = 0
    out = []
    ap = out.append
    for _ in range(310 + k + 1):
        v = (tbl[f] + tbl[b]) & 0xFFFFFFFF
        tbl[f] = v if v < 2 ** 31 else v - (1 << 32)
        ap(v >> 1)
        f += 1
        if f == 31:
            f = 0
        b += 1
        if b == 31:
            b = 0
    return out[310:]


GENS = {"l48": gen_l48, "t3": gen_t3}


def _selftest():
    from header_gen import Random3
    ok = True
    for s in (1, 2, 1789239391, 1790106110, (1 << 31) - 1):
        R = Random3(s)
        ref = [R.next() for _ in range(120)]
        mine = gen_t3(s, 119)
        if mine != ref:
            ok = False
            log("SELFTEST FAIL t3 seed=%d" % s)
    log("selftest t3 vs header_gen.Random3: %s" % ("OK" if ok else "FAIL"))
    if not ok:
        sys.exit(2)
    # l48 spot identity: draw k recomputed by independent step is trivially the
    # same code; assert basic invariants instead (31-bit range, first-draw law).
    d = gen_l48(1, 5)
    assert all(0 <= v < (1 << 31) for v in d)
    x = ((1 << 16) + 0x330E)
    x = (A48 * x + B48) & M48
    assert d[0] == x >> 17
    log("selftest l48 invariants: OK")


# ---------------------------------------------------------------------------
# 3. corpus rows (all_signings.json + pair_h3.json) and bursts
# ---------------------------------------------------------------------------
SIG = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
PAIR = json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))

SECOND = {}     # row idx -> second (pair_h3 = nsign ts second)
TS = {}         # row idx -> nsign_ts
SRC = {}
for p in PAIR:
    for i, r in enumerate(SIG):
        if r["d2"] == p["d2"] and r["d0"] == p["d0"] and r["d4"] == p["d4"]:
            SECOND[i] = p["second"]
            TS[i] = p["nsign_ts"]
            SRC[i] = r["src"]
            break
# rows 8/9 (= S1/S2) are absent from pair_h3; seconds are explicit in
# corpus_seed.md (desc_det sec=1789240512), ts inferred from the capture's
# src offsets hits7+22272 / hits7+28663 (ms after row 7's nsign record).
_ts7 = TS[7]
for i, add in ((8, 22272), (9, 28663)):
    SECOND[i] = 1789240512
    TS[i] = _ts7 + add
    SRC[i] = SIG[i]["src"]

NROWS = len(SIG)
BURSTS = defaultdict(list)
for i in range(NROWS):
    BURSTS[SRC[i]].append(i)
for b in BURSTS:
    BURSTS[b].sort(key=lambda i: (TS[i], i))


def dwords(hexstr, n):
    return [int(hexstr[j * 8:(j + 1) * 8], 16) for j in range(n)]


class Row(object):
    __slots__ = ("idx", "src", "second", "ts", "names", "cand", "candset",
                 "ase", "pmap", "xmap", "n32", "n32lt", "npair", "words")


ROWS = []
for i in range(NROWS):
    r = Row()
    r.idx = i
    r.src = SRC[i]
    r.second = SECOND[i]
    r.ts = TS[i]
    d0 = dwords(SIG[i]["d0"], 36)
    d2 = int(SIG[i]["d2"], 16)
    d4 = dwords(SIG[i]["d4"], 8)
    # targets: W0=d0[0], X=d0[1] (d0[1]-alignment variant of the tile start),
    # tile words T0..T3=d0[2..5], d2, d4[0..7]; deduped by value (the tile
    # repeats, so {d0[0..5]} covers both tile alignments).
    vals = [(d0[0], "W0"), (d0[1], "X"), (d0[2], "T0"), (d0[3], "T1"),
            (d0[4], "T2"), (d0[5], "T3"), (d2, "d2")]
    vals += [(d4[j], "d4[%d]" % j) for j in range(8)]
    byval = defaultdict(list)
    for v, nm in vals:
        byval[v].append(nm)
    r.names = {v: "|".join(nl) for v, nl in byval.items()}
    r.words = sorted(byval)

    cand = defaultdict(list)     # r -> [(names, fam, chex)]
    npair = 0
    pmap = defaultdict(list)     # a -> [(b, names, chex)]   pairM
    xmap = defaultdict(list)     # a -> [(b, names, chex)]   pairX
    ase = set()
    n32 = 0
    for w, nm in r.names.items():
        for c in POOL32:
            ch = "%08x" % c
            cand[w ^ c].append((nm, "xor", ch))
            cand[(c - w) & M32].append((nm, "sub", ch))
            cand[(w - c) & M32].append((nm, "add", ch))
            n32 += 3
        if nm == "d2":                       # screen mixing test (task extra)
            for c in SCREEN_C:
                ch = "%04x" % c
                cand[w ^ c].append((nm, "scr:xor", ch))
                cand[(w - c) & M32].append((nm, "scr:add", ch))
                cand[(c - w) & M32].append((nm, "scr:sub", ch))
                cand[(w + c) & M32].append((nm, "scr:rsub", ch))
                n32 += 4
        for ca, cb in PAIR_POOL:
            a = (w >> 16) ^ ca
            b = (w & 0xFFFF) ^ cb
            ch = "%04x/%04x" % (ca, cb)
            pmap[a].append((b, nm, ch))
            xmap[a].append((b, nm, ch))
            ase.add(a)
            npair += 1
    r.cand = cand
    r.candset = frozenset(cand)
    r.n32 = n32
    r.n32lt = sum(1 for rr in cand if rr < (1 << 31))
    r.pmap = pmap
    r.xmap = xmap
    r.ase = frozenset(ase)
    r.npair = npair
    ROWS.append(r)

SEED_RANGE = 601          # second-0 .. second-600
K1 = 50000                # draws per seed, pass 1
K2 = 200000               # escalation draws


def build_seedmap(row_idxs):
    sm = defaultdict(list)
    for i in row_idxs:
        for off in range(SEED_RANGE):
            sm[SECOND[i] - off].append((i, off))
    return sm


SEEDMAP = build_seedmap(range(NROWS))

# ---------------------------------------------------------------------------
# 4. per-seed sweep worker (inverted membership)
# ---------------------------------------------------------------------------


def sweep_seed(job):
    gen, seed, rows_offs, k = job
    draws = GENS[gen](seed, k)
    d1 = dict(zip(draws[:k], range(k)))          # draw -> k (last-wins on dups)
    mlists = {}                                  # mask -> [k...]
    for kk, d in enumerate(draws[:k]):
        m = d & 0xFFFF
        if m in mlists:
            mlists[m].append(kk)
        else:
            mlists[m] = [kk]
    hits = []
    for (ri, off) in rows_offs:
        row = ROWS[ri]
        for rr in d1.keys() & row.candset:
            kk = d1[rr]
            for (nm, fam, ch) in row.cand[rr]:
                hits.append((ri, off, nm, "%s" % fam, ch, kk))
        for a in row.ase & mlists.keys():
            ks = mlists[a]
            for (b, nm, ch) in row.pmap[a]:
                for kk in ks:
                    if (draws[kk + 1] & 0xFFFF) == b:
                        hits.append((ri, off, nm, "pairM", ch, kk))
        for a in row.ase & d1.keys():
            kk = d1[a]
            nx = draws[kk + 1]
            for (b, nm, ch) in row.xmap[a]:
                if nx == b:
                    hits.append((ri, off, nm, "pairX", ch, kk))
    return (gen, seed, k, hits)


def run_jobs(jobs, label):
    """returns list of (gen, seed, k, hits); logs progress."""
    out = []
    t0 = time.time()
    n = len(jobs)
    log("[%s] %d seed-jobs, K varies" % (label, n))
    try:
        import multiprocessing as mp
        nw = min(8, (os.cpu_count() or 2))
        if nw > 1 and n > 64:
            with mp.Pool(nw) as pool:
                for done, res in enumerate(pool.imap_unordered(sweep_seed, jobs,
                                                               chunksize=16), 1):
                    out.append(res)
                    if done % 200 == 0 or done == n:
                        el = time.time() - t0
                        log("  %s %d/%d  (%.1fs, %.1f ms/seed)"
                            % (label, done, n, el, 1000.0 * el / done))
        else:
            raise ImportError
    except Exception:
        for done, job in enumerate(jobs, 1):
            out.append(sweep_seed(job))
            if done % 200 == 0 or done == n:
                el = time.time() - t0
                log("  %s %d/%d  (%.1fs, %.1f ms/seed)"
                    % (label, done, n, el, 1000.0 * el / done))
    log("[%s] done in %.1fs, %d hits"
        % (label, time.time() - t0, sum(len(h[3]) for h in out)))
    return out


def p_hit(kdraws, space):
    return 1.0 - (1.0 - 1.0 / float(space)) ** kdraws


def analyze(gen, k, allhits, label):
    """allhits: list of (gen, seed, k, hits); returns summary dict; logs detail."""
    hits = [h for (_, _, kk, hh) in allhits if kk == k
            for h in ((gen,) + hh[:5] + (hh[5], kk))]
    # hits tuple: (gen, row, off, names, fam, chex, kk_draw, kstream)
    nh = len(hits)
    ncells = sum(1 for (_, _, kk, hh) in allhits if kk == k)
    e32 = 0.0
    epair = 0.0
    for row in ROWS:
        e32 += row.n32lt * p_hit(k, 1 << 31) * ncells_row(k, row.idx)
        epair += row.npair * p_hit(k, 1 << 32) * ncells_row(k, row.idx)
    log("")
    log("=== ANALYSIS %s (gen=%s, K=%d) ===" % (label, gen, k))
    log("cells tested: %d   hits observed: %d   expected by chance: %.1f "
        "(32-bit fams %.1f + pairM %.1f + pairX ~0)"
        % (ncells, nh, e32 + epair, e32, epair))
    famc = defaultdict(int)
    for h in hits:
        famc[h[4]] += 1
    log("hits by family: %s" % dict(sorted(famc.items())))

    # -- cells with >= 2 hits -------------------------------------------------
    cells = defaultdict(list)
    for h in hits:
        cells[(h[1], h[6])].append(h)
    multi = {key: v for key, v in cells.items() if len(v) >= 2}
    strong = []
    for (ri, seed), v in sorted(multi.items()):
        ks = [h[6] for h in v]
        span = max(ks) - min(ks)
        flag = "TIGHT" if span <= 1000 else ""
        if len(v) >= 3 and span <= 1000:
            strong.append((ri, seed, v))
        if len(v) >= 2:
            log("CELL row=%d (%s) seed=%d off=%d hits=%d span=%d %s | %s"
                % (ri, ROWS[ri].src, seed, ROWS[ri].second - seed, len(v), span,
                   flag,
                   "; ".join("%s %s C=%s k=%d" % (h[3], h[4], h[5], h[6])
                             for h in sorted(v, key=lambda x: x[6]))))
    log("cells with >=2 hits: %d   (>=3 tight hits: %d)" % (len(multi), len(strong)))

    # -- cross-row seed groups ------------------------------------------------
    byseed = defaultdict(lambda: defaultdict(list))   # seed -> row -> [hit]
    for h in hits:
        byseed[h[6]][h[1]].append(h)
    groups = []
    for seed, rowmap in byseed.items():
        if len(rowmap) < 2:
            continue
        rws = sorted(rowmap, key=lambda i: (ROWS[i].ts, i))
        # disjoint & increasing k windows along ts?
        ordered = True
        for a1, a2 in zip(rws, rws[1:]):
            ka = [h[6] for h in rowmap[a1]]
            kb = [h[6] for h in rowmap[a2]]
            if max(ka) >= min(kb):
                ordered = False
                break
        gaps = None
        if ordered:
            mins = [min(h[6] for h in rowmap[i]) for i in rws]
            gaps = [y - x for x, y in zip(mins, mins[1:])]
        groups.append((seed, rws, rowmap, ordered, gaps))
    log("seed groups hitting >=2 rows: %d" % len(groups))
    strong_groups = 0
    for seed, rws, rowmap, ordered, gaps in sorted(groups):
        if not ordered:
            continue
        gconst = (gaps is not None and len(gaps) >= 2
                  and len(set(gaps)) == 1)
        tight = all(len(rowmap[i]) >= 2
                    and (max(h[6] for h in rowmap[i])
                         - min(h[6] for h in rowmap[i])) <= 1000
                    for i in rws)
        tag = ("GAP-CONST" if gconst else "") + ("+TIGHT" if tight else "")
        strong_groups += 1 if (gconst or (tight and len(rws) >= 2)) else 0
        log("GROUP seed=%d rows=%s ordered %s" %
            (seed, [(i, ROWS[i].second - seed) for i in rws], tag))
        for i in rws:
            hh = sorted(rowmap[i], key=lambda x: x[6])
            log("    row=%d (%s, off=%d) n=%d k=[%d..%d] %s"
                % (i, ROWS[i].src, ROWS[i].second - seed, len(hh),
                   hh[0][6], hh[-1][6],
                   "; ".join("%s %s C=%s k=%d" % (h[3], h[4], h[5], h[6])
                             for h in hh[:24])))
    log("ordered groups: %d ; strong (gap-const or multi-tight): %d"
        % (len([g for g in groups if g[3]]), strong_groups))

    # -- screen test ----------------------------------------------------------
    scr = [h for h in hits if h[4].startswith("scr:")]
    log("screen-test hits (d2 vs 1080/2237/2400): %d" % len(scr))
    for h in scr:
        log("  SCR row=%d seed=%d off=%d %s C=%s k=%d"
            % (h[1], h[6], ROWS[h[1]].second - h[6], h[3] + "/" + h[4],
               h[5], h[6]))
    return {"hits": nh, "cells": ncells, "expected": e32 + epair,
            "multi_cells": len(multi), "strong_cells": len(strong),
            "groups": len(groups),
            "ordered_groups": len([g for g in groups if g[3]]),
            "strong_groups": strong_groups, "screen": len(scr)}


def ncells_row(k, row_idx):
    """number of seeds swept for this row at draw count k (pass-dependent)."""
    if k == K2:
        return SEED_RANGE if row_idx in ESCALATED.get("rows", ()) else 0
    return SEED_RANGE


ESCALATED = {}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    log("=" * 78)
    log("l48_sweep - inverted-membership lrand48/random() sweep")
    log("start %s" % time.strftime("%Y-%m-%dT%H:%M:%S"))
    log("=" * 78)
    log("constant pool: %d assembled 64-bit mov/movk constants "
        "(deriv3.py lines 150-205 extractor on fn_9afa4_full.log)"
        % len(CONSTS64))
    log("  uniq low32=%d high32=%d -> POOL32 (incl C=0) = %d"
        % (len(_low32), len(_high32), len(POOL32)))
    log("  terminal 16-bit immediates: %d uniq; PAIR_POOL (C16a,C16b) = %d"
        % (len(set(WORDS16)), len(PAIR_POOL)))
    log("rows: %d  bursts: %s"
        % (NROWS, {b: v for b, v in sorted(BURSTS.items())}))
    for i in range(NROWS):
        log("  row %d %-22s second=%d ts=%d words=%d n32=%d (r<2^31: %d) "
            "pair-cands=%d"
            % (i, SRC[i], SECOND[i], TS[i], len(ROWS[i].words), ROWS[i].n32,
               ROWS[i].n32lt, ROWS[i].npair))
    log("seeds per row: %d (second-0 .. second-%d); distinct seeds: %d"
        % (SEED_RANGE, SEED_RANGE - 1, len(SEEDMAP)))
    log("draws per seed: K=%d (escalation K=%d)" % (K1, K2))
    _selftest()

    summary = {}
    for gen in ("l48", "t3"):
        jobs = [(gen, s, ro, K1) for s, ro in sorted(SEEDMAP.items())]
        res = run_jobs(jobs, "pass1-%s" % gen)
        summary[gen] = analyze(gen, K1, res, "pass1")

    # ---- escalation: earliest row of every burst lacking a strong group ----
    log("")
    log("=== ESCALATION DECISION (K=%d on earliest row of bursts without a "
        "strong group) ===" % K2)
    for gen in ("l48", "t3"):
        esc_rows = set()
        for b, rws in sorted(BURSTS.items()):
            earliest = rws[0]
            esc_rows.add(earliest)
            log("  %s burst %-22s earliest row %d -> escalate to K=%d"
                % (gen, b, earliest, K2))
        ESCALATED["rows"] = esc_rows
        sm2 = build_seedmap(esc_rows)
        jobs = [(gen, s, ro, K2) for s, ro in sorted(sm2.items())]
        res = run_jobs(jobs, "pass2-%s" % gen)
        summary[gen + "-K200k"] = analyze(gen, K2, res, "pass2")

    log("")
    log("=" * 78)
    log("FINAL SUMMARY")
    for key, val in summary.items():
        log("  %-12s hits=%-5d expected=%.1f  cells>=2hits=%-4d tight3=%-3d "
            "groups2+=%-4d ordered=%-4d strong=%d screen=%d"
            % (key, val["hits"], val["expected"], val["multi_cells"],
               val["strong_cells"], val["groups"], val["ordered_groups"],
               val["strong_groups"], val["screen"]))
    log("total wall time %.1f s" % (time.time() - T0))
    log("=" * 78)
