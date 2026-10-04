#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
l48_pairs.py - PAIR-XOR validation sweep (extends the NEGATIVE simple-mix
sweep l48_sweep.py after the static pin of the rand opcode):

    static disasm 0x12a2fc/0x12a31c:  bl rand (PLT 0x148d10) -> push(0x147630),
    bl rand, push, pop, pop, `eor w2,w0,w21` @0x12a368, push
    ==> each consumed unit = rand_k ^ rand_{k+1}   (two consecutive draws)

Model: srand48(resume_second) once per nOnResume (0x12cbc0); the stream
advances across signings within one process; wire word = XOR of a small
window of consecutive lrand48 draws (+ optional per-site constant C).

ORCHESTRATOR ANCHOR (re-verified in pass 0):
    row 7 W0 = 0x13271271 = d[2k] ^ d[2k+1]  for srand48(1789240512),
    k = 107110 (pair index; = draws 214220/214221).

STATIC CONFIRMATION (dumped 0x12a2c0..0x12a424 during this validation): the
wire-builder rand loop is

    0x12a2f8  ldr x21,[x20]; bl rand @0x12a2fc; mov w2,w0; bl 0x147630 (push)
    0x12a31c  bl rand; mov w2,w0; bl 0x147630 (push)
    0x12a340  bl 0x147734 (pop -> w21 = rand2)
    0x12a358  bl 0x147734 (pop -> w0  = rand1)
    0x12a368  eor w2,w0,w21
    0x12a370  bl 0x147630 (push unit)
    0x12a388  bl 0x14784c (stack op, w2=1)
    0x12a39c / 0x12a3b4  pop, pop
    0x12a3d0  bl 0x146ed8 (emit w2=first pop, w3=second pop)
    0x12a3f4  add w2,w0,#1 ; push  (index counter)
    0x12a414  cbnz w0, #0x12a2f8   (LOOP)

i.e. each iteration consumes EXACTLY the draws (2j, 2j+1) and produces the
unit d[2j]^d[2j+1] (the only two bl rand sites in the whole library are in
this loop, so all draws flow through it in order).  The block contains NO
mix constant - the pure pair-XOR reading.  The emitted (w2,w3) = (index,
value) pair feeds the serializer 0x146ed8.

STRUCTURAL FACT used throughout: bionic rand() == lrand48 is 31-bit, so ANY
XOR of draws (pair / triple / quad / skip-1 / running-chain) has bit31 = 0.
Wire words with bit31 = 1 (row 7 X/U0/U1/d2, rows 8/9 W0/U0/U1/d2, ...) are
IMPOSSIBLE for the pure-XOR family and are only testable as
w = pxor ^ C (C from the mov/movk site-constant pool).

Forms swept (all vectorized over the draw array d):
    pair  d[2j] ^ d[2j+1]         (PROVEN unit; j = pair index)
    adj   d[i] ^ d[i+1]           (overlapping cross-check superset)
    sk1   d[i] ^ d[i+2]           (skip-1)
    t3    d[i] ^ d[i+1] ^ d[i+2]  (triple)
    t4    d[i] ^ d[i+1] ^ d[i+2] ^ d[i+3]  (quad)
    chain xor-accumulate(d)       (running state: w_n = r_n ^ w_{n-1})

Passes:
  0  anchor verification + exact chance accounting
  A  full sweep: rows 0..9 x seeds second-0..-600 x 2M draws, all forms
     pure + pxor^C; tight-cell and cross-row structure detectors
  B  stride scan: seed 1789240512, draw window 214220+-20000, gap g=1..256,
     w =?= d[k'] ^ d[k'+g] (+ ^C); multi-word same-g structures
  C  cross-signing: seed 1789240512 x 10M draws (5M pairs): rows 7/8/9 pure
     full-range + pxor^C full-range & in prioritized windows; k-ordering
     vs the anchor
  D  fresh-3: signings_extract.json parse attempt (task's section map vs
     corpus_seed.md) + 44 body dwords (BE/LE) vs seeds sec-0..-3 and a
     single-resume 4M-draw model; pure + pxor^C

Outputs: l48_pairs.log (full detail) + SUMMARY at end.
"""
import json
import os
import re
import sys
import time
from collections import defaultdict

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
M48 = (1 << 48) - 1
A48 = 0x5DEECE66D
B48 = 0xB
M31 = (1 << 31) - 1
SPACE = float(1 << 31)          # XOR-of-draws value space (31-bit)

LOG_PATH = os.path.join(HERE, "l48_pairs.log")
LOGF = None                     # opened in main only (workers must not truncate)


def log(msg=""):
    print(msg, flush=True)
    if LOGF is not None:
        LOGF.write(msg + "\n")


# ---------------------------------------------------------------------------
# constant pool (same extractor logic as l48_sweep.py: fn_9afa4_full.log)
# ---------------------------------------------------------------------------
RE_MOVI = re.compile(r"^0x([0-9a-f]+)\s+(mov|movk)\s+([wx]\d+|xzr|wzr),\s*"
                     r"#(0x[0-9a-f]+|\d+)(?:,\s*lsl\s*#(\d+))?\s*$")
M32 = 0xFFFFFFFF


def _chains_from_lines(lines):
    """mov/movk immediate chains (corpus_seed_lcg.py extract_constants logic):
    any register switch or foreign instruction closes the chain; EVERY chain
    (including movk-continued prefixes) contributes low32+high32 candidates."""
    chain_reg = None
    chain_val = 0
    freq = defaultdict(int)

    def close():
        nonlocal chain_reg, chain_val
        if chain_reg is not None:
            freq[chain_val & 0xFFFFFFFFFFFFFFFF] += 1
        chain_reg = None
        chain_val = 0

    for line in lines:
        m = RE_MOVI.match(line)
        if not m:
            close()
            continue
        op, reg = m.group(2), m.group(3)
        if reg.startswith("w"):
            reg = "x" + reg[1:]
        imm = int(m.group(4), 0)
        lsl = int(m.group(5) or 0)
        if reg == "xzr" or reg == "wzr":
            close()
            continue
        if op == "mov":
            if chain_reg != reg:
                close()
            chain_reg = reg
            chain_val = imm & 0xFFFFFFFF
        else:
            if chain_reg != reg:
                close()
                chain_reg = reg
                chain_val = 0
            chain_val = (chain_val | (imm << lsl)) & 0xFFFFFFFFFFFFFFFF
    close()
    vals = set()
    for v in freq:
        vals.add(v & M32)
        vals.add((v >> 32) & M32)
    return vals


def _build_pool():
    """C pool = mov/movk chains of sub_9afa4 (fn_9afa4_full.log, the
    descriptor-fill function used by l48_sweep) UNION the mov/movk chains of
    the rand opcode block neighborhood (0x12a200..0x12a500).  The block
    itself (dumped: 0x12a2f8 loop, bl rand x2, pop/pop, eor w2,w0,w21, push,
    emit via 0x146ed8 with an index counter) contains NO mix constants -
    the pure pair-XOR reading - so the pool stays small on purpose."""
    vals = _chains_from_lines(open(os.path.join(HERE, "fn_9afa4_full.log"),
                                   encoding="utf-8", errors="replace"))
    n_9afa4 = len(vals)
    vm_vals = set()
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        sys.path.insert(0, HERE)
        from decryptors import LIB
        elf = open(LIB, "rb").read()
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        lines = ["0x%x  %s %s" % (ins.address, ins.mnemonic, ins.op_str)
                 for ins in md.disasm(elf[0x12A200:0x12A500], 0x12A200)]
        vm_vals = _chains_from_lines(lines)
    except Exception as e:
        print("rand-block pool extraction failed (%s)" % e)
    pool = sorted((vals | vm_vals | {0}))
    return pool, n_9afa4, len(vm_vals)


POOL32, NPOOL_9AFA4, NPOOL_VM = _build_pool()
POOL32_ARR = np.array(POOL32, dtype=np.uint32)

# ---------------------------------------------------------------------------
# corpus rows (all_signings.json + pair_h3.json) - mapping identical to l48_sweep
# ---------------------------------------------------------------------------
SIG = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
PAIR = json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))

SECOND, TS, SRC = {}, {}, {}
for p in PAIR:
    for i, r in enumerate(SIG):
        if r["d2"] == p["d2"] and r["d0"] == p["d0"] and r["d4"] == p["d4"]:
            SECOND[i] = p["second"]
            TS[i] = p["nsign_ts"]
            SRC[i] = r["src"]
            break
_ts7 = TS[7]
for i, add in ((8, 22272), (9, 28663)):
    SECOND[i] = 1789240512
    TS[i] = _ts7 + add
    SRC[i] = SIG[i]["src"]

NROWS = len(SIG)


def dwords(hexstr, n):
    return [int(hexstr[j * 8:(j + 1) * 8], 16) for j in range(n)]


class Row(object):
    __slots__ = ("idx", "src", "second", "ts", "words", "names", "pxable",
                 "cimpossible")


ROWS = []
for i in range(NROWS):
    r = Row()
    r.idx = i
    r.src = SRC[i]
    r.second = SECOND[i]
    r.ts = TS[i]
    d0 = dwords(SIG[i]["d0"], 6)
    d2 = int(SIG[i]["d2"], 16)
    d4 = dwords(SIG[i]["d4"], 8)
    vals = [(d0[0], "W0"), (d0[1], "X"), (d0[2], "T0"), (d0[3], "T1"),
            (d0[4], "T2"), (d0[5], "T3"), (d2, "d2")]
    vals += [(d4[j], "d4[%d]" % j) for j in range(8)]
    byval = defaultdict(list)
    for v, nm in vals:
        byval[v].append(nm)
    r.names = {v: "|".join(nl) for v, nl in byval.items()}
    r.words = sorted(byval)
    # pure-XOR testable = value has bit31 == 0
    r.pxable = [v for v in r.words if not (v >> 31)]
    r.cimpossible = [v for v in r.words if (v >> 31)]
    ROWS.append(r)


# ---------------------------------------------------------------------------
# generator + forms
# ---------------------------------------------------------------------------
def gen_l48(seed, n):
    """first n lrand48 draws after srand48(seed) as uint32 numpy array."""
    x = ((seed << 16) + 0x330E) & M48
    out = []
    ap = out.append
    a, b, m = A48, B48, M48
    for _ in range(n):
        x = (a * x + b) & m
        ap(x >> 17)
    return np.array(out, dtype=np.uint32)


def forms(d):
    """dict name -> uint32 array of XOR-window values (all 31-bit).
    'pair' is the STATICALLY PROVEN unit: the loop 0x12a2f8..0x12a414 draws
    two rands per iteration and emits eor(r1,r2) - unit_j = d[2j] ^ d[2j+1].
    'adj' (overlapping) is kept only as a cross-check superset."""
    f = {}
    f["pair"] = d[0::2] ^ d[1::2]
    f["adj"] = d[:-1] ^ d[1:]
    f["sk1"] = d[:-2] ^ d[2:]
    t2 = d[:-2] ^ d[1:-1]
    f["t3"] = t2 ^ d[2:]
    t3v = t2[:-1] ^ d[2:-1]
    f["t4"] = t3v ^ d[3:]
    f["chain"] = np.bitwise_xor.accumulate(d)
    return f


def c_targets(row):
    """distinct {w ^ C < 2^31} values with (word, C) tags for a row."""
    tv = []
    tags = {}
    for w, nm in row.names.items():
        for c in POOL32:
            t = (w ^ c) & M32
            if not (t >> 31):
                tags.setdefault(t, []).append((nm, c))
                tv.append(t)
    return np.array(sorted(set(tv)), dtype=np.uint32), tags


CT = {}      # row idx -> (targets array, tags)
for _i, _r in enumerate(ROWS):
    CT[_i] = c_targets(_r)


def search_hits(sorted_arr, targets):
    """indices into targets that are present in sorted_arr."""
    if len(targets) == 0:
        return []
    pos = np.searchsorted(sorted_arr, targets)
    pos_c = np.clip(pos, 0, len(sorted_arr) - 1)
    eq = sorted_arr[pos_c] == targets
    return list(np.nonzero(eq)[0])


def resolve_k(unsorted_arr, value):
    ks = np.nonzero(unsorted_arr == np.uint32(value))[0]
    return [int(k) for k in ks[:8]]


# ---------------------------------------------------------------------------
# pass A worker (multiprocessing)
# ---------------------------------------------------------------------------
SEED_RANGE = 601
K_A = 2000000


def seedmap():
    sm = defaultdict(list)
    for i in range(NROWS):
        for off in range(SEED_RANGE):
            sm[SECOND[i] - off].append((i, off))
    return sm


def passA_job(job):
    seed, cells = job
    d = gen_l48(seed, K_A)
    F = forms(d)
    del d
    Fs = {nm: np.sort(a) for nm, a in F.items()}
    fpair_sorted = Fs["pair"]
    pure, cfam = [], []
    for (ri, off) in cells:
        row = ROWS[ri]
        tp = np.array(sorted(set(row.pxable)), dtype=np.uint32)
        for nm, s in Fs.items():
            for ti in search_hits(s, tp):
                v = int(tp[ti])
                for k in resolve_k(F[nm], v):
                    pure.append((ri, off, row.names[v], nm, v, k))
        # C-family ONLY on the proven pair unit: w = d[2j]^d[2j+1] ^ C
        tc, tags = CT[ri]
        for ti in search_hits(fpair_sorted, tc):
            v = int(tc[ti])
            for (wnm, c) in tags[v]:
                for k in resolve_k(F["pair"], v):
                    cfam.append((ri, off, wnm, c, "pair", v, k))
    return seed, pure, cfam


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    LOGF = open(LOG_PATH, "w", encoding="utf-8", buffering=1)
    T0 = time.time()
    log("=" * 78)
    log("l48_pairs - pair-XOR validation sweep")
    log("start %s" % time.strftime("%Y-%m-%dT%H:%M:%S"))
    log("=" * 78)
    log("constant pool: fn_9afa4 chains -> %d low/high32 candidates; VM wire-"
        "builder region 0xfb00..0x12f000 -> %d ; POOL32 (union incl 0) = %d"
        % (NPOOL_9AFA4, NPOOL_VM, len(POOL32)))
    log("rows: %d" % NROWS)
    for r in ROWS:
        log("  row %d %-22s second=%d ts=%d" % (r.idx, r.src, r.second, r.ts))
        log("        pxable (bit31=0, pure-XOR testable): %s"
            % ["%s=%08x" % (r.names[v], v) for v in r.pxable])
        log("        bit31=1 (impossible pure, C-family only): %s"
            % ["%s=%08x" % (r.names[v], v) for v in r.cimpossible])

    # ------------------------------------------------------------------ 0
    log("")
    log("=" * 78)
    log("PASS 0 - anchor verification")
    log("=" * 78)
    A0 = gen_l48(1789240512, 214240)
    w0 = int(A0[214220]) ^ int(A0[214221])
    log("d[214220]=%08x d[214221]=%08x xor=%08x  (row7 W0 = 13271271) match=%s"
        % (int(A0[214220]), int(A0[214221]), w0, w0 == 0x13271271))
    log("anchor: pair k=107110 (draws 214220/214221), seed 1789240512")
    # chance for the orchestrator's exact test: rows 7/8/9 x their pxable
    # words x 400k pairs, pure pair-XOR:
    npx = sum(len(ROWS[i].pxable) for i in (7, 8, 9))
    e_orch = npx * 400000.0 / SPACE
    log("chance for orchestrator test (3 rows x %d pxable words x 400k pairs):"
        " %.4f hits" % (npx, e_orch))
    log("chance for full 16 words x 3 rows x 400k pairs (if bit31 ignored): "
        "%.4f" % (48 * 400000.0 / SPACE))

    # ------------------------------------------------------------------ A
    log("")
    log("=" * 78)
    log("PASS A - full sweep rows 0..9 x seeds second-0..-600 x %d draws" % K_A)
    log("=" * 78)
    SM = seedmap()
    ncells = sum(len(v) for v in SM.values())
    npx_tot = sum(len(r.pxable) for r in ROWS)
    eA_pure = 0.0
    for i in range(NROWS):
        pos = 6 * K_A                      # ~ positions over the 6 forms
        eA_pure += SEED_RANGE * len(ROWS[i].pxable) * pos / SPACE
    eA_c = 0.0
    for i in range(NROWS):
        eA_c += SEED_RANGE * len(CT[i][0]) * (K_A // 2) / SPACE
    log("cells (row,off): %d ; distinct seeds: %d" % (ncells, len(SM)))
    log("expected chance hits: pure ~%.1f ; pxor^C ~%.1f" % (eA_pure, eA_c))
    jobs = sorted(SM.items())
    t0 = time.time()
    results = []
    try:
        import multiprocessing as mp
        nw = min(10, (os.cpu_count() or 2))
        with mp.Pool(nw) as pool:
            done = 0
            for res in pool.imap_unordered(passA_job, jobs, chunksize=8):
                results.append(res)
                done += 1
                if done % 100 == 0 or done == len(jobs):
                    el = time.time() - t0
                    log("  passA %d/%d seeds (%.1fs, %.0f ms/seed)"
                        % (done, len(jobs), el, 1000.0 * el / done))
    except Exception as e:
        log("mp failed (%s) - single process fallback" % e)
        results = [passA_job(j) for j in jobs]
    pure_hits = [h for (_, p, _) in results for h in p]
    c_hits = [h for (_, _, c) in results for h in c]
    log("passA done %.1fs: pure hits=%d (expected %.1f), pxor^C hits=%d "
        "(expected %.1f)" % (time.time() - t0, len(pure_hits), eA_pure,
                             len(c_hits), eA_c))

    log("")
    log("-- pass A pure hits (all) --")
    for (ri, off, wnm, fam, v, k) in sorted(pure_hits):
        log("  PURE row=%d (%s) seed=%d off=%d word=%s val=%08x form=%s "
            "drawk=%d pairk=%.1f"
            % (ri, ROWS[ri].src, SECOND[ri] - off, off, wnm, v, fam, k,
               k / 2.0))
    log("-- pass A pxor^C hits: aggregate only (all-forms noise too high to "
        "list); structured cells below --")
    cby = defaultdict(list)
    for (ri, off, wnm, c, fam, v, k) in c_hits:
        cby[(ri, off)].append((k, wnm, c))
    maxcell = max((len(v) for v in cby.values()), default=0)
    log("pxor^C cells: %d ; max hits in one cell: %d (real signing would "
        "cluster ~10-16 units in one cell)" % (len(cby), maxcell))
    ncellc2 = 0
    for (ri, off), hh in sorted(cby.items()):
        if len(hh) >= 2:
            hh = sorted(hh)
            span = hh[-1][0] - hh[0][0]
            if span <= 2000:
                ncellc2 += 1
                if ncellc2 <= 40:
                    log("  CC2 row=%d seed=%d off=%d hits=%d span=%d: %s"
                        % (ri, SECOND[ri] - off, off, len(hh), span,
                           ["%s C=%08x k=%d" % (w, c, k) for (k, w, c) in hh]))
            elif len(hh) >= 6:
                log("  CC6 row=%d seed=%d off=%d hits=%d span=%d (wide): %s"
                    % (ri, SECOND[ri] - off, off, len(hh), span,
                       ["%s C=%08x k=%d" % (w, c, k) for (k, w, c) in hh[:8]]))
    log("pxor^C cells with >=2 hits span<=2000: %d (chance expects ~%.0f)"
        % (ncellc2, 6010 * (eA_c / max(ncells, 1)) ** 2 / 2 * (2 * 2000.0 / (K_A // 2))))

    # structure detectors
    def cells_of(hits, kidx):
        by = defaultdict(list)
        for h in hits:
            by[(h[0], h[1])].append(h)
        return by

    log("")
    log("-- pass A structure: cells with >=2 pure hits span<=20000 --")
    ncell2 = 0
    for (ri, off), hh in cells_of(pure_hits, 5).items():
        if len(hh) >= 2:
            ks = sorted(h[5] for h in hh)
            if ks[-1] - ks[0] <= 20000:
                ncell2 += 1
                log("  CELL2 row=%d seed=%d off=%d pure hits=%d span=%d: %s"
                    % (ri, SECOND[ri] - off, off, len(hh), ks[-1] - ks[0],
                       ["%s %s k=%d" % (h[2], h[3], h[5]) for h in
                        sorted(hh, key=lambda x: x[5])]))
    log("cells>=2 pure (span<=20000): %d" % ncell2)
    log("-- pass A cross-row: same seed hitting >=2 rows (PURE only), "
        "ordered k by ts --")
    ngrp = 0
    byseed = defaultdict(lambda: defaultdict(list))
    for h in pure_hits:
        byseed[SECOND[h[0]] - h[1]][h[0]].append(h)
    for seed, rm in sorted(byseed.items()):
        if len(rm) < 2:
            continue
        rws = sorted(rm, key=lambda i: TS[i])
        ordered = all(max(h[5] for h in rm[a])
                      < min(h[5] for h in rm[b])
                      for a, b in zip(rws, rws[1:]))
        ngrp += 1
        log("  GROUP seed=%d rows=%s ordered=%s hits/row=%s"
            % (seed, rws, ordered,
               {i: len(rm[i]) for i in rws}))
    log("same-seed multi-row groups (pure): %d" % ngrp)

    # ------------------------------------------------------------------ B
    log("")
    log("=" * 78)
    log("PASS B - stride scan around the anchor (seed 1789240512)")
    log("=" * 78)
    A0PAIR = 107110
    A0DRAW = 214220
    W = 20000
    lo, hi = A0DRAW - W, A0DRAW + W
    dB = gen_l48(1789240512, hi + 300)
    row7 = ROWS[7]
    tp7 = np.array(sorted(set(row7.pxable)), dtype=np.uint32)
    tc7, tags7 = CT[7]
    bhits = []          # (g, k, word) pure
    bchits = []         # (g, k, word, C)
    for g in range(1, 257):
        seg = dB[lo:hi] ^ dB[lo + g:hi + g]
        sseg = np.sort(seg)
        for ti in search_hits(sseg, tp7):
            v = int(tp7[ti])
            for k in resolve_k(seg, v):
                bhits.append((g, lo + k, row7.names[v]))
        for ti in search_hits(sseg, tc7):
            v = int(tc7[ti])
            for (wnm, c) in tags7[v]:
                for k in resolve_k(seg, v):
                    bchits.append((g, lo + k, wnm, c))
    eB_pure = len(row7.pxable) * 256 * (2 * W) / SPACE
    eB_c = len(tc7) * 256 * (2 * W) / SPACE
    log("window draw k' in [%d..%d], g=1..256; expected chance: pure %.2f, "
        "pxor^C %.1f" % (lo, hi, eB_pure, eB_c))
    log("-- pass B pure hits --")
    for (g, k, wnm) in sorted(bhits):
        mark = "  <== ANCHOR" if (g == 1 and k == A0DRAW) else ""
        log("  g=%-3d k'=%d (pair %.1f, dK=%+d) word=%s%s"
            % (g, k, k / 2.0, k - A0DRAW, wnm, mark))
    log("-- pass B pxor^C hits --")
    for (g, k, wnm, c) in sorted(bchits):
        log("  g=%-3d k'=%d (pair %.1f, dK=%+d) word=%s C=%08x"
            % (g, k, k / 2.0, k - A0DRAW, wnm, c))
    log("-- pass B structures: same g, >=2 distinct words --")
    bygap_p = defaultdict(set)
    for (g, k, wnm) in bhits:
        bygap_p[g].add((wnm, k))
    bygap_c = defaultdict(set)
    for (g, k, wnm, c) in bchits:
        bygap_c[g].add((wnm, k, c))
    nst = 0
    for g in sorted(set(bygap_p) | set(bygap_c)):
        wp = sorted(bygap_p.get(g, ()))
        wc = sorted(bygap_c.get(g, ()))
        if len(wp) >= 2 or len(wc) >= 2:
            nst += 1
            log("  g=%d pure=%s C=%s" % (g, wp, wc))
    log("same-g multi-word structures: %d" % nst)
    del dB

    # ------------------------------------------------------------------ C
    log("")
    log("=" * 78)
    log("PASS C - cross-signing: seed 1789240512 x 10M draws (5M pairs)")
    log("=" * 78)
    KC = 10000000
    dC = gen_l48(1789240512, KC)
    FC = forms(dC)
    FsC = {nm: np.sort(a) for nm, a in FC.items()}
    eC = {}
    cpure = []          # (ri, form, pairk, wordname) pure hits for the ordering test
    for ri in (7, 8, 9):
        row = ROWS[ri]
        tp = np.array(sorted(set(row.pxable)), dtype=np.uint32)
        eC[ri] = len(tp) * (5 * KC) / SPACE
        log("-- row %d (%s) pure full-range hits (expected chance %.2f) --"
            % (ri, row.src, eC[ri]))
        found = 0
        for nm, s in FsC.items():
            for ti in search_hits(s, tp):
                v = int(tp[ti])
                for k in resolve_k(FC[nm], v):
                    found += 1
                    cpure.append((ri, nm, k // 2, row.names[v]))
                    log("  PURE row=%d word=%s val=%08x form=%s drawk=%d "
                        "pairk=%d dPair=%s%d"
                        % (ri, row.names[v], v, nm, k, k // 2,
                           "+" if k // 2 >= A0PAIR else "-", abs(k // 2 - A0PAIR)))
        if found == 0:
            log("  none")
        # pxor^C full range (count + tight clusters only)
        tc, tags = CT[ri]
        chere = []
        for nm, s in FsC.items():
            for ti in search_hits(s, tc):
                v = int(tc[ti])
                for (wnm, c) in tags[v]:
                    for k in resolve_k(FC[nm], v):
                        chere.append((wnm, c, nm, k))
        e = len(tc) * (5 * KC) / SPACE
        log("  pxor^C full-range hits: %d (expected chance %.1f)" % (len(chere), e))
        # tight cluster detector (pairs within span 2000)
        hh = sorted(chere, key=lambda x: x[3])
        cl = 0
        for a_i in range(len(hh)):
            for b_i in range(a_i + 1, len(hh)):
                if hh[b_i][3] - hh[a_i][3] > 2000:
                    break
                cl += 1
                if cl <= 12:
                    log("    TIGHT pair k=%d..%d: %s / %s"
                        % (hh[a_i][3], hh[b_i][3], hh[a_i][:3], hh[b_i][:3]))
        if cl == 0:
            log("    no tight (span<=2000) pxor^C clusters")
        # prioritized windows: pair [107110, 112110] and +2000..+7000
        for (p_lo, p_hi, tag) in ((A0PAIR, A0PAIR + 5000, "next-signing"),
                                  (A0PAIR + 2000, A0PAIR + 7000, "stride+2k")):
            wlo, whi = 2 * p_lo, 2 * p_hi + 4
            chw = []
            for (wnm, c, nm, k) in chere:
                if wlo <= k <= whi:
                    chw.append((wnm, c, nm, k))
            log("  window pair[%d..%d] (%s): pxor^C hits=%d (expected %.2f)"
                % (p_lo, p_hi, tag, len(chw),
                   len(tc) * (whi - wlo) / SPACE))
            for (wnm, c, nm, k) in chw:
                log("    word=%s C=%08x form=%s drawk=%d pairk=%d"
                    % (wnm, c, nm, k, k // 2))
    # cross-signing ordering verdict (rows 7/8/9 = same process, consecutive):
    # a REAL model needs min pairk(row8) > max pairk(row7) >= anchor, etc.
    log("-- pass C ordering test (pure hits, pair k) --")
    c_order = True
    for ri in (7, 8, 9):
        ks = sorted(pk for (r, _, pk, _) in cpure if r == ri)
        log("  row %d: %d pure hits, pair k = %s"
            % (ri, len(ks), ks[:20]))
    for a, b in zip((7, 8), (8, 9)):
        ka = [pk for (r, _, pk, _) in cpure if r == a]
        kb = [pk for (r, _, pk, _) in cpure if r == b]
        if ka and kb and max(ka) >= min(kb):
            c_order = False
    log("  ordered 7<8<9 (where hits exist): %s ; hit rows: %s"
        % (c_order, sorted(set(r for (r, _, _, _) in cpure))))
    del dC, FC, FsC

    # ------------------------------------------------------------------ D
    log("")
    log("=" * 78)
    log("PASS D - fresh-3 (device/java_dump/signings_extract.json)")
    log("=" * 78)
    FRESH_PATH = os.path.join(os.path.dirname(HERE), "device", "java_dump",
                              "signings_extract.json")
    fresh = json.load(open(FRESH_PATH, encoding="utf-8"))["signings"]
    log("fresh signings: %d" % len(fresh))
    for s in fresh:
        blob = s["blob"]
        log("  n=%d ts=%d blob=%d bytes header=%s..." % (s["n"], s["ts"],
                                                         len(blob) // 2,
                                                         blob[:32]))
    # parse attempt per the task's section map (d0 36dw @body0, #2 @144B,
    # #4 @148B, #7 @180B)
    log("-- parse attempt per task section map (body = blob[16:], 44 dwords) --")
    ok_parse = True
    for s in fresh:
        body = bytes.fromhex(s["blob"])[16:]
        ndw = len(body) // 4
        need = 36 + 1 + 8 + 1
        log("  n=%d body dwords=%d ; task map d0(36)+#2(1)+#4(8)+#7(1)=%d%s"
            % (s["n"], ndw, need,
               " FITS" if need <= ndw else " + claims dwords OVERFLOWS body"))
        w0p = int.from_bytes(body[0:4], "big")
        d2p = int.from_bytes(body[144:148], "big")
        log("    naive parse: W0=%08x X=%08x d2@144=%08x"
            % (w0p, int.from_bytes(body[4:8], "big"), d2p))
    # needle check (re-verify corpus_seed.md): #9/#8 constants, H, screen ints
    needles = {
        "d9": bytes.fromhex("fad0f10d60f93c17"),
        "d8": bytes.fromhex("bffffffffffffd1f"),
        "1080be": (1080).to_bytes(4, "big"),
        "2237be": (2237).to_bytes(4, "big"),
    }
    nn = 0
    for s in fresh:
        blob = bytes.fromhex(s["blob"])
        h = bytes.fromhex(s["H"])
        for wname, wbytes in needles.items():
            if wbytes in blob:
                nn += 1
        for j in range(0, 26):
            if h[j:j + 4] in blob:
                nn += 1
    log("needle hits in fresh blobs (d9/d8/screen/H-windows): %d "
        "(corpus_seed.md says 0 -> descriptors NOT in wire body)" % nn)
    # model test on all 44 body dwords (BE as stored + LE byte order)
    forms_names = ("adj", "sk1", "t3", "t4", "chain")
    KF = 4000000
    log("-- fresh-3 model test: 44 body dwords (BE+LE) vs lrand48 pxor forms --")
    allhits = []
    exp_tot = 0.0
    FSEC = {1: 1790106110, 2: 1790106176, 3: 1790106196}   # header-inverted
    for s in fresh:
        sec = FSEC[s["n"]]
        body = bytes.fromhex(s["blob"])[16:]
        words = []
        for j in range(len(body) // 4):
            wbe = int.from_bytes(body[4 * j:4 * j + 4], "big")
            wle = int.from_bytes(body[4 * j:4 * j + 4], "little")
            words.append((wbe, "dw%d" % j))
            if wle != wbe:
                words.append((wle, "dw%d/LE" % j))
        px = sorted(set(v for v, _ in words if not (v >> 31)))
        tp = np.array(px, dtype=np.uint32)
        npxf = len(px)
        # per-signing seeds: sec-0..-3 ; plus single-resume below
        for off in range(4):
            seed = sec - off
            d = gen_l48(seed, KF)
            F = forms(d)
            Fs = {nm: np.sort(a) for nm, a in F.items()}
            e = npxf * (5 * KF) / SPACE
            exp_tot += e
            hits_here = []
            for nm, sa in Fs.items():
                for ti in search_hits(sa, tp):
                    v = int(tp[ti])
                    for k in resolve_k(F[nm], v):
                        nmw = [n for vv, n in words if vv == v]
                        hits_here.append((seed, nmw[0], nm, v, k))
                        allhits.append((s["n"], seed, nmw[0], nm, v, k))
            if hits_here:
                for (sd, wnm, nm, v, k) in hits_here:
                    log("  FRESH-HIT n=%d seed=%d (sec-%d) word=%s val=%08x "
                        "form=%s k=%d" % (s["n"], sd, sec - sd, wnm, v, nm, k))
            del d, F, Fs
        log("  n=%d sec=%d pxable body words=%d: per-seed expected ~%.2f, "
            "swept 4 seeds x %d draws" % (s["n"], sec, npxf,
                                          npxf * (5 * KF) / SPACE, KF))
    # single-resume model: one srand48 at signing-1's second, stream shared
    log("-- fresh-3 single-resume model: seed in {1790106110-o, o=0..3}, "
        "shared stream, 3 signings anywhere in 0..%d draws --" % KF)
    for off in range(4):
        seed = 1790106110 - off
        d = gen_l48(seed, KF)
        F = forms(d)
        Fs = {nm: np.sort(a) for nm, a in F.items()}
        tp_all = {}
        for s in fresh:
            body = bytes.fromhex(s["blob"])[16:]
            words = []
            for j in range(len(body) // 4):
                wbe = int.from_bytes(body[4 * j:4 * j + 4], "big")
                wle = int.from_bytes(body[4 * j:4 * j + 4], "little")
                words.append((wbe, "n%ddw%d" % (s["n"], j)))
                if wle != wbe:
                    words.append((wle, "n%ddw%d/LE" % (s["n"], j)))
            px = sorted(set(v for v, _ in words if not (v >> 31)))
            tp_all[s["n"]] = (np.array(px, dtype=np.uint32),
                              {v: n for v, n in words if not (v >> 31)})
        hits_here = 0
        exp_tot += sum(len(tp) for tp, _ in tp_all.values()) * (5 * KF) / SPACE
        for nm, sa in Fs.items():
            for sn, (tp, nmmap) in tp_all.items():
                for ti in search_hits(sa, tp):
                    v = int(tp[ti])
                    for k in resolve_k(F[nm], v):
                        hits_here += 1
                        allhits.append((sn, seed, nmmap[v], nm, v, k))
                        log("  FRESH-HIT(single-resume) n=%d seed=%d word=%s "
                            "val=%08x form=%s k=%d"
                            % (sn, seed, nmmap[v], v, nm, k))
        log("  seed=%d: %d hits" % (seed, hits_here))
        del d, F, Fs
    log("fresh-3 total pure hits: %d (expected chance ~%.1f)"
        % (len(allhits), exp_tot))

    # ------------------------------------------------------------------ sum
    log("")
    log("=" * 78)
    log("SUMMARY")
    log("=" * 78)
    log("anchor verified: row7 W0=13271271 = d[214220]^d[214221], "
        "srand48(1789240512), pair k=107110")
    log("pass A: pure=%d (exp %.1f)  pxor^C=%d (exp %.1f)  "
        "cells>=2 pure span20k=%d  cells>=2 C span2k=%d  groups=%d"
        % (len(pure_hits), eA_pure, len(c_hits), eA_c, ncell2, ncellc2, ngrp))
    log("pass B: pure=%d (exp %.2f)  pxor^C=%d (exp %.1f)  same-g "
        "multi-word structures=%d" % (len(bhits), eB_pure, len(bchits),
                                      eB_c, nst))
    log("pass C: rows 7/8/9 pure full-range and pxor^C - see detail above")
    log("pass D: fresh-3 pure hits=%d - see detail above" % len(allhits))
    log("total wall time %.1f s" % (time.time() - T0))
    log("=" * 78)
    LOGF.close()
