"""_sub_seedscan.py — wide VECTORIZED seed scan for the iOS adj9 16-byte header.

Hypothesis under test:  header = 4 BE uint32 words, each < 2^31, computed as
w[j] = d[2j] ^ d[2j+1] for 8 draws d0..d7 of a PRNG seeded by
seed = capture_second + K (K in a wide window), for:

  * TYPE_3  — bionic rand() (== glibc random(), deg=31 sep=3, 310 warm-up
              discards, MINSTD Schrage init).  Vectorized port must FIRST be
              proven byte-equal to adj9_signer.Random3 (the Android-verified
              ground truth) on 100 random seeds + edge cases.
  * LCG48   — srand48/lrand48 (a=0x5DEECE66D, c=0xB, X=(seed<<16)|0x330E,
              out = X>>17), warm-ups 0..64, K in +/-100,000,000.

Plus TARGETED epoch seeds (not scanned): unix-978307200 (Apple epoch),
unix+2082844800 (1904 epoch), unix*1000 truncated to 31 / 32 bits, and a
warm-up sweep W in 0..4096 for TYPE_3 (and LCG48, bonus) at seed = unix.

Scans are exact (no probability): every candidate (second, K) pair in the
declared windows is evaluated against every observed header.  A 128-bit
4-word match cannot occur by chance (2^-128 per pair); a w0-only prefilter
(24-bit Bloom table over the 28 observed w0 values) is exact-or-superset and
every candidate it emits is re-verified with the scalar ground-truth
generator, all four words.

Inputs  : the Fiddler SAZ (raw/NNNN_c.txt Authorization signature=...,
          raw/NNNN_m.xml ClientBeginRequest, ISO with +05:30).
Outputs : console log + _sub_seedscan_RESULT.md next to this file.
          No other file is modified (adj9_signer is imported read-only,
          bytecode writing disabled).
"""
from __future__ import annotations

import base64
import calendar
import os
import re
import struct
import sys
import time
import zipfile

import numpy as np

sys.dont_write_bytecode = True                    # do not touch __pycache__
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import adj9_signer as android_ref                 # ground truth (read-only)

SAZ = r"C:\Users\Apps\Downloads\cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
RESULT_MD = os.path.join(_HERE, "_sub_seedscan_RESULT.md")

# ---------------------------------------------------------------- constants
M31 = (1 << 31) - 1          # 2147483647
A31, Q31, R31 = 16807, 127773, 2836          # MINSTD Schrage
MASK32 = (1 << 32) - 1
MASK48 = (1 << 48) - 1
MASK64 = (1 << 64) - 1
A48, C48 = 0x5DEECE66D, 0xB                  # lrand48
GOLDEN = 0x9E3779B97F4A7C15                  # Bloom hash multiplier
FILTER_BITS = 24

K_WINDOW_TYPE3 = 5_000_000                   # +/- 5,000,000 s  (~58 days)
K_WINDOW_LCG48 = 100_000_000                 # +/- 100,000,000 s (~3.2 years)
CHUNK = 200_000                              # seeds per vectorized block
LCG48_N_DRAWS = 72                           # covers warm-ups W = 0..64
LCG48_WARMUPS = list(range(0, 65))           # 0..64 inclusive
EPOCH_APPLE = 978307200                      # 2001-01-01T00:00:00Z
EPOCH_1904 = 2_082_844_800                   # 1904-01-01T00:00:00Z
WARM_SWEEP_MAX = 4096                        # targeted warm-up sweep

LOG_LINES: list[str] = []


def log(msg=""):
    print(msg, flush=True)
    LOG_LINES.append(str(msg))


# ======================================================================
# 1. DATA — (approx_unix_second, header16) pairs from the SAZ
# ======================================================================
_TS_RE = re.compile(r'ClientBeginRequest="([^"]+)"')
_ISO_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d+))?(?:([+-])(\d{2}):?(\d{2}))?")


def iso_to_unix(s: str) -> int:
    m = _ISO_RE.match(s.strip())
    if not m:
        raise ValueError("bad timestamp %r" % s)
    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    off = 0
    if m.group(8):
        off = (1 if m.group(8) == "+" else -1) \
            * (int(m.group(9)) * 3600 + int(m.group(10)) * 60)
    return calendar.timegm((y, mo, d, h, mi, se, 0, 0, 0)) - off


def load_pairs():
    """-> (pairs, n_signed_requests).
    pairs: list of dicts {T (min capture second), hdr (16 B), reqs,
                          secs (every capture second seen with this header)}
    sorted by T.  One entry per unique 16-byte header."""
    z = zipfile.ZipFile(SAZ)
    by_header: dict[bytes, list[int]] = {}
    n_signed = 0
    for name in sorted(z.namelist()):
        if not name.endswith("_c.txt"):
            continue
        text = z.read(name).decode("utf-8", errors="replace")
        m = re.search(r'signature="([^"]+)"', text)
        if not m:
            continue
        blob = base64.b64decode(m.group(1))
        header = blob[:16]
        xml = z.read(name[:-6] + "_m.xml").decode("utf-8", errors="replace")
        sec = iso_to_unix(_TS_RE.search(xml).group(1))
        n_signed += 1
        by_header.setdefault(header, []).append(sec)
    pairs = [{"T": min(v), "hdr": h, "reqs": len(v), "secs": sorted(set(v))}
             for h, v in by_header.items()]
    pairs.sort(key=lambda p: p["T"])
    return pairs, n_signed


# ======================================================================
# 2. SCALAR GROUND TRUTH (independent, arbitrary warm-up)
# ======================================================================
class Type3Scalar:
    """Scalar TYPE_3 identical to adj9_signer.Random3 but with a caller-set
    warm-up count (Random3 hard-codes 310)."""

    def __init__(self, seed, n_warm=310):
        r = self.r = [0] * 31
        s = seed & MASK32
        if s == 0:
            s = 1
        w = s if s < (1 << 31) else s - (1 << 32)
        r[0] = w
        prev = w
        for i in range(1, 31):
            if prev >= 0:
                hi = prev // Q31
                lo = prev - hi * Q31
            else:
                hi = -((-prev) // Q31)
                lo = prev - hi * Q31
            word = A31 * lo - R31 * hi
            if word < 0:
                word += M31
            prev = word
            r[i] = word
        self.f, self.b = 3, 0
        for _ in range(n_warm):
            self.next()

    def next(self):
        v = (self.r[self.f] + self.r[self.b]) & MASK32
        self.r[self.f] = v if v < (1 << 31) else v - (1 << 32)
        o = v >> 1
        self.f = (self.f + 1) % 31
        self.b = (self.b + 1) % 31
        return o


class LCG48Scalar:
    """srand48/lrand48 scalar reference."""

    def __init__(self, seed):
        self.X = ((seed & MASK32) << 16) | 0x330E

    def next(self):
        self.X = (self.X * A48 + C48) & MASK48
        return self.X >> 17


def type3_words_scalar(seed, n_warm=310):
    g = Type3Scalar(seed, n_warm)
    d = [g.next() for _ in range(8)]
    return tuple(d[2 * i] ^ d[2 * i + 1] for i in range(4))


def lcg48_words_scalar(seed, n_warm=0):
    g = LCG48Scalar(seed)
    for _ in range(n_warm):
        g.next()
    d = [g.next() for _ in range(8)]
    return tuple(d[2 * i] ^ d[2 * i + 1] for i in range(4))


# ======================================================================
# 3. VECTORIZED GENERATORS (numpy, uint32/uint64)
# ======================================================================
def type3_chunk(seeds, n_warm=310, want_draws=False):
    """seeds: (N,) uint64 -> (words (4,N) uint32, draws (8,N) uint32 or None).

    The 31-word TYPE_3 state of all N seeds lives in ONE (31, N) uint32
    matrix (row i = state word i; contiguous rows so every per-step op is a
    whole-row numpy op).  State words are stored as their unsigned 32-bit
    values: r[f] = signed(v) is later read only through
    (r[f] + r[b]) & 0xFFFFFFFF, which is identical in unsigned arithmetic.
    The signed interpretation matters only in the MINSTD init chain from
    r[0], handled in int64 above (incl. the r[0] < 0 branch for seeds
    >= 2^31)."""
    seeds = np.asarray(seeds, dtype=np.uint64)
    N = seeds.size
    s0 = (seeds & np.uint64(MASK32)).astype(np.uint32)
    s0[s0 == 0] = 1
    st = np.empty((31, N), dtype=np.uint32)
    st[0] = s0
    prev = s0.astype(np.int64)
    prev = np.where(prev >= (1 << 31), prev - (1 << 32), prev)
    for i in range(1, 31):
        if int(prev.min()) >= 0:
            hi = prev // Q31
        else:
            hi = np.where(prev >= 0, prev // Q31, -((-prev) // Q31))
        lo = prev - hi * Q31
        word = A31 * lo - R31 * hi
        word = np.where(word < 0, word + M31, word)
        st[i] = word.astype(np.uint32)
        prev = word
    f, b = 3, 0
    draws = np.empty((8, N), dtype=np.uint32)
    for t in range(n_warm + 8):
        v = st[f] + st[b]
        st[f] = v
        if t >= n_warm:
            draws[t - n_warm] = v >> np.uint32(1)
        f = (f + 1) % 31
        b = (b + 1) % 31
    words = draws[0::2] ^ draws[1::2]
    return (words, draws) if want_draws else (words, None)


def lcg48_draws_chunk(seeds, n_draws=LCG48_N_DRAWS):
    """seeds: (N,) uint64 -> draws (n_draws, N) uint32, draw t = output of
    lrand48 call t+1 after srand48(seed).  The 48-bit LCG multiply
    X*a mod 2^48 is done exactly via a 24/24-bit split (X*a < 2^83 overflows
    uint64): X = xh*2^24 + xl -> (xh*a mod 2^24)*2^24 + (xl*a mod 2^48)."""
    seeds = np.asarray(seeds, dtype=np.uint64)
    N = seeds.size
    X = ((seeds & np.uint64(MASK32)) << np.uint64(16)) | np.uint64(0x330E)
    a = np.uint64(A48)
    c = np.uint64(C48)
    m24 = np.uint64(0xFFFFFF)
    m48 = np.uint64(MASK48)
    s24 = np.uint64(24)
    s17 = np.uint64(17)
    draws = np.empty((n_draws, N), dtype=np.uint32)
    for t in range(n_draws):
        xh = X >> s24
        xl = X & m24
        X = ((((xh * a) & m24) << s24) + ((xl * a) & m48)) & m48
        X = (X + c) & m48
        draws[t] = (X >> s17).astype(np.uint32)
    return draws


# ======================================================================
# 4. CROSS-CHECKS (must pass before any scan)
# ======================================================================
def cross_checks():
    log("=== CROSS-CHECK 1: vectorized TYPE_3 vs adj9_signer.Random3 ===")
    rng = np.random.default_rng(20261001)
    seeds = [int(x) for x in rng.integers(0, 1 << 32, 100, dtype=np.uint64)]
    seeds += [0, 1, 2, MASK32, 1 << 31, (1 << 31) - 1, 123459876,
              EPOCH_APPLE, 1787553341, 1790341508, 1790694158,
              (1787553341 + EPOCH_1904) & MASK32,        # >= 2^31 (neg r[0])
              (1787553341 * 1000) & 0x7FFFFFFF]
    bad = 0
    for s in seeds:
        ref = android_ref.Random3(s)
        d_ref = [ref.next() for _ in range(8)]
        w_ref = [d_ref[2 * i] ^ d_ref[2 * i + 1] for i in range(4)]
        w_vec, d_vec = type3_chunk(np.array([s], dtype=np.uint64),
                                   n_warm=310, want_draws=True)
        d_list = [int(x) for x in d_vec[:, 0]]
        w_list = [int(x) for x in w_vec[:, 0]]
        if d_list != d_ref or w_list != w_ref:
            bad += 1
            log("  MISMATCH seed=%d" % s)
    assert bad == 0, "vectorized TYPE_3 != Random3 on %d seeds" % bad
    log("  100 random + 13 edge seeds: all 8 draws and 4 XOR words "
        "EQUAL  -> PASS")

    log("=== CROSS-CHECK 2: vectorized TYPE_3 header vs adj9_signer."
        "make_header on the 9 genuine ANDROID captures ===")
    for g in android_ref.GOLD_VECTORS:
        hdr_ref = bytes(android_ref.make_header(g["second"]))
        w_vec, _ = type3_chunk(np.array([g["second"]], dtype=np.uint64))
        hdr_vec = b"".join(struct.pack(">I", int(x)) for x in w_vec[:, 0])
        assert hdr_vec == hdr_ref, "gold second %d" % g["second"]
    log("  9/9 gold seconds reproduce make_header byte-exactly  -> PASS")

    log("=== CROSS-CHECK 3: vectorized LCG48 vs scalar lrand48 ===")
    seeds = [int(x) for x in rng.integers(0, 1 << 32, 100, dtype=np.uint64)]
    seeds += [0, 1, MASK32, 1 << 31, 1787553341, (1787553341 * 1000) & 0x7FFFFFFF]
    for s in seeds:
        g = LCG48Scalar(s)
        d_ref = [g.next() for _ in range(LCG48_N_DRAWS)]
        d_vec = lcg48_draws_chunk(np.array([s], dtype=np.uint64))
        assert [int(x) for x in d_vec[:, 0]] == d_ref, "seed %d" % s
        # words for every warm-up W in 0..64 must match the scalar law
        for W in (0, 1, 7, 31, 64):
            assert tuple(int(x) for x in
                         (d_vec[W + 0, 0] ^ d_vec[W + 1, 0],
                          d_vec[W + 2, 0] ^ d_vec[W + 3, 0],
                          d_vec[W + 4, 0] ^ d_vec[W + 5, 0],
                          d_vec[W + 6, 0] ^ d_vec[W + 7, 0])) \
                == lcg48_words_scalar(s, W)
    log("  106 seeds x 72 draws + spot warm-ups: EQUAL  -> PASS")

    log("=== CROSS-CHECK 4: scalar Type3Scalar (arbitrary warm-up) vs "
        "Random3 ===")
    for s in seeds[:20]:
        d_ref = []
        r = android_ref.Random3(s)
        d_ref = [r.next() for _ in range(8)]
        g = Type3Scalar(s, 310)
        d_own = [g.next() for _ in range(8)]
        assert d_own == d_ref, "seed %d" % s
    log("  20 seeds: warm-up-310 streams EQUAL  -> PASS")


# ======================================================================
# 5. SCAN MACHINERY (Bloom prefilter on w0 + exact scalar verification)
# ======================================================================
def build_w0_filter(target_w0):
    size = 1 << (FILTER_BITS - 6)                    # uint64 words
    table = np.zeros(size, dtype=np.uint64)
    for t in target_w0:
        h = ((t * GOLDEN) & MASK64) >> (64 - FILTER_BITS)
        table[h >> 6] |= np.uint64(1) << np.uint64(h & 63)
    return table


def filter_w0(table, w0):
    """w0: uint32 array -> bool mask (exact-or-superset of w0 membership)."""
    h = (w0.astype(np.uint64) * np.uint64(GOLDEN)) >> np.uint64(64 - FILTER_BITS)
    return (table[h >> np.uint64(6)] >> (h & np.uint64(63))) \
        & np.uint64(1) != 0


def verify_candidate(gen, W, seed, pairs):
    """Exact 4-word check of one candidate against every observed header.
    Returns list of (header_hex, [K per capture second])."""
    if gen == "TYPE_3":
        w = type3_words_scalar(seed, W)
    elif gen == "LCG48":
        w = lcg48_words_scalar(seed, W)
    else:
        raise ValueError(gen)
    out = []
    for p in pairs:
        tw = struct.unpack(">4I", p["hdr"])
        if w == tw:
            out.append((p["hdr"].hex(), [seed - s for s in p["secs"]]))
    return out


def scan_type3(seed_lo, seed_hi, pairs, table, n_warm=310, label=""):
    t0 = time.perf_counter()
    n_cand = 0
    hits = []
    total = seed_hi - seed_lo + 1
    for start in range(seed_lo, seed_hi + 1, CHUNK):
        stop = min(start + CHUNK - 1, seed_hi)
        seeds = np.arange(start, stop + 1, dtype=np.uint64)
        w, _ = type3_chunk(seeds, n_warm=n_warm)
        idxs = np.nonzero(filter_w0(table, w[0]))[0]
        for i in idxs:
            n_cand += 1
            for hh, ks in verify_candidate("TYPE_3", n_warm,
                                           start + int(i), pairs):
                hits.append({"gen": "TYPE_3/%d warm-up" % n_warm, "W": n_warm,
                             "seed": start + int(i), "header": hh, "K": ks})
        done = stop - seed_lo + 1
        if (start - seed_lo) // CHUNK % 10 == 0 or done == total:
            log("  [%s] %d/%d seeds (%.1f%%) cands=%d hits=%d  %.1fs"
                % (label, done, total, 100.0 * done / total, n_cand,
                   len(hits), time.perf_counter() - t0))
    return hits, {"seeds": total, "chunks": (total + CHUNK - 1) // CHUNK,
                  "candidates": n_cand, "secs": time.perf_counter() - t0}


def scan_lcg48(seed_lo, seed_hi, pairs, table, label=""):
    t0 = time.perf_counter()
    n_cand = 0
    hits = []
    total = seed_hi - seed_lo + 1
    for start in range(seed_lo, seed_hi + 1, CHUNK):
        stop = min(start + CHUNK - 1, seed_hi)
        seeds = np.arange(start, stop + 1, dtype=np.uint64)
        draws = lcg48_draws_chunk(seeds)
        x0 = draws[:-1] ^ draws[1:]                  # x0[t] = w0 for warm-up t
        for W in LCG48_WARMUPS:
            idxs = np.nonzero(filter_w0(table, x0[W]))[0]
            for i in idxs:
                n_cand += 1
                for hh, ks in verify_candidate("LCG48", W,
                                               start + int(i), pairs):
                    hits.append({"gen": "LCG48/%d warm-up" % W, "W": W,
                                 "seed": start + int(i), "header": hh,
                                 "K": ks})
        done = stop - seed_lo + 1
        if (start - seed_lo) // CHUNK % 50 == 0 or done == total:
            log("  [%s] %d/%d seeds (%.1f%%) cands=%d hits=%d  %.1fs"
                % (label, done, total, 100.0 * done / total, n_cand,
                   len(hits), time.perf_counter() - t0))
    return hits, {"seeds": total, "chunks": (total + CHUNK - 1) // CHUNK,
                  "candidates": n_cand, "secs": time.perf_counter() - t0}


# ======================================================================
# 6. TARGETED TESTS (exact epoch seeds + warm-up sweeps, no K scan)
# ======================================================================
def targeted_tests(pairs):
    hits = []
    log("=== TARGETED epoch seeds (exact, both generators) ===")
    for p in pairs:
        T = p["T"]
        tw = struct.unpack(">4I", p["hdr"])
        cand = {
            "unix-978307200 (Apple epoch)": T - EPOCH_APPLE,
            "unix+2082844800 (1904 epoch)": (T + EPOCH_1904) & MASK32,
            "(unix*1000) & (2^31-1)": (T * 1000) & 0x7FFFFFFF,
            "(unix*1000) & (2^32-1)": (T * 1000) & MASK32,
        }
        for name, seed in cand.items():
            w = type3_words_scalar(seed, 310)
            if w == tw:
                h = {"gen": "TYPE_3/310 warm-up", "W": 310, "seed": seed,
                     "header": p["hdr"].hex(),
                     "K": [seed - s for s in p["secs"]],
                     "epoch": name}
                hits.append(h)
                log("  HIT %s T=%d seed=%d (%s)" % (p["hdr"].hex(), T, seed, name))
            for W in LCG48_WARMUPS:
                w = lcg48_words_scalar(seed, W)
                if w == tw:
                    h = {"gen": "LCG48/%d warm-up" % W, "W": W, "seed": seed,
                         "header": p["hdr"].hex(),
                         "K": [seed - s for s in p["secs"]],
                         "epoch": name}
                    hits.append(h)
                    log("  HIT %s T=%d seed=%d W=%d (%s)"
                        % (p["hdr"].hex(), T, seed, W, name))
    log("  epoch-seed pass done (%d hits so far)" % len(hits))

    log("=== TARGETED warm-up sweep W=0..%d (seed = unix, and epoch seeds) "
        "=== " % WARM_SWEEP_MAX)
    for p in pairs:
        T = p["T"]
        tw = struct.unpack(">4I", p["hdr"])
        sweep_seeds = {"unix": T,
                       "unix-978307200": (T - EPOCH_APPLE) & MASK32,
                       "unix+2082844800": (T + EPOCH_1904) & MASK32,
                       "(unix*1000)&31b": (T * 1000) & 0x7FFFFFFF}
        for name, seed in sweep_seeds.items():
            # --- TYPE_3: stream of 4104 outputs from a 0-warm-up generator
            g = Type3Scalar(seed, 0)
            d = np.array([g.next() for _ in range(WARM_SWEEP_MAX + 8)],
                         dtype=np.uint64)
            x0 = d[:-1] ^ d[1:]                       # x0[W] = w0 for warm-up W
            m = (x0[: WARM_SWEEP_MAX + 1] == tw[0])
            for j in range(1, 4):
                m &= (x0[2 * j: 2 * j + WARM_SWEEP_MAX + 1] == tw[j])
            for W in np.nonzero(m)[0]:
                hits.append({"gen": "TYPE_3/%d warm-up" % int(W), "W": int(W),
                             "seed": int(seed), "header": p["hdr"].hex(),
                             "K": [int(seed) - s for s in p["secs"]],
                             "epoch": name + " (sweep)"})
                log("  HIT %s T=%d seed=%d TYPE_3 W=%d (%s)"
                    % (p["hdr"].hex(), T, seed, int(W), name))
            # --- LCG48: same sweep (bonus coverage)
            g = LCG48Scalar(seed)
            d = np.array([g.next() for _ in range(WARM_SWEEP_MAX + 8)],
                         dtype=np.uint64)
            x0 = d[:-1] ^ d[1:]
            m = (x0[: WARM_SWEEP_MAX + 1] == tw[0])
            for j in range(1, 4):
                m &= (x0[2 * j: 2 * j + WARM_SWEEP_MAX + 1] == tw[j])
            for W in np.nonzero(m)[0]:
                hits.append({"gen": "LCG48/%d warm-up" % int(W), "W": int(W),
                             "seed": int(seed), "header": p["hdr"].hex(),
                             "K": [int(seed) - s for s in p["secs"]],
                             "epoch": name + " (sweep)"})
                log("  HIT %s T=%d seed=%d LCG48 W=%d (%s)"
                    % (p["hdr"].hex(), T, seed, int(W), name))
    log("  warm-up sweep done (%d hits total)" % len(hits))
    return hits


# ======================================================================
# 7. MAIN
# ======================================================================
def main():
    t_start = time.perf_counter()
    log("_sub_seedscan.py — wide vectorized seed scan for the iOS adj9 header")
    log("python %s / numpy %s" % (sys.version.split()[0], np.__version__))
    log("")

    pairs, n_signed = load_pairs()
    log("=== DATA: %s ===" % os.path.basename(SAZ))
    log("  signed requests: %d   unique 16-byte headers: %d" %
        (n_signed, len(pairs)))
    span = pairs[-1]["T"] - pairs[0]["T"]
    log("  capture-second range: %d .. %d  (span %d s = %.1f min)" %
        (pairs[0]["T"], pairs[-1]["T"], span, span / 60.0))
    n31 = sum(1 for p in pairs
              if all(x < (1 << 31) for x in struct.unpack(">4I", p["hdr"])))
    log("  headers with all 4 words < 2^31: %d/%d" % (n31, len(pairs)))
    for p in pairs:
        log("    T=%d  x%d  %s" % (p["T"], p["reqs"], p["hdr"].hex()))
    log("")

    cross_checks()
    log("")

    target_w0 = [struct.unpack(">4I", p["hdr"])[0] for p in pairs]
    table = build_w0_filter(target_w0)

    # ---- sanity: plant a synthetic ANDROID-known target and recover it ----
    log("=== SANITY: recover a known Android header through the scan "
        "machinery ===")
    gs = android_ref.GOLD_VECTORS[0]["second"]
    synth = [{"T": gs, "hdr": bytes(android_ref.make_header(gs)),
              "reqs": 1, "secs": [gs]}]
    stab = build_w0_filter([struct.unpack(">4I", synth[0]["hdr"])[0]])
    shits, _ = scan_type3(gs - 1000, gs + 1000, synth, stab,
                          label="sanity")
    assert any(h["seed"] == gs and h["K"] == [0] for h in shits), \
        "sanity scan failed to recover K=0"
    log("  synthetic header recovered at seed=%d K=0 W=310  -> PASS" % gs)
    log("")

    all_hits = []

    # ---------------- SCAN 1: TYPE_3, K in [-5e6, +5e6] ----------------
    lo1 = pairs[0]["T"] - K_WINDOW_TYPE3
    hi1 = pairs[-1]["T"] + K_WINDOW_TYPE3
    log("=== SCAN 1: bionic TYPE_3 (310 warm-up), seed = second + K, "
        "K in [%+d, %+d] ===" % (-K_WINDOW_TYPE3, K_WINDOW_TYPE3))
    log("  union seed range %d .. %d (%d seeds; covers every (second,K) pair "
        "for all %d headers = %d (second,K) evaluations)"
        % (lo1, hi1, hi1 - lo1 + 1, len(pairs),
           len(pairs) * (2 * K_WINDOW_TYPE3 + 1)))
    h1, s1 = scan_type3(lo1, hi1, pairs, table, n_warm=310, label="TYPE_3")
    all_hits += h1
    log("  -> TYPE_3 wide scan: %d seeds, %d chunks, %d prefilter "
        "candidates, %d exact hits, %.1f s"
        % (s1["seeds"], s1["chunks"], s1["candidates"], len(h1), s1["secs"]))
    log("")

    # ---------------- SCAN 2: srand48/lrand48, K in [-1e8, +1e8] --------
    lo2 = pairs[0]["T"] - K_WINDOW_LCG48
    hi2 = pairs[-1]["T"] + K_WINDOW_LCG48
    log("=== SCAN 2: srand48/lrand48, warm-ups 0..64, seed = second + K, "
        "K in [%+d, %+d] ===" % (-K_WINDOW_LCG48, K_WINDOW_LCG48))
    log("  union seed range %d .. %d (%d seeds; covers every (second,K,W) "
        "for all %d headers = %d (second,K) x 65 W evaluations)"
        % (lo2, hi2, hi2 - lo2 + 1, len(pairs),
           len(pairs) * (2 * K_WINDOW_LCG48 + 1)))
    h2, s2 = scan_lcg48(lo2, hi2, pairs, table, label="LCG48")
    all_hits += h2
    log("  -> LCG48 wide scan: %d seeds, %d chunks, %d prefilter "
        "candidates, %d exact hits, %.1f s"
        % (s2["seeds"], s2["chunks"], s2["candidates"], len(h2), s2["secs"]))
    log("")

    # ---------------- SCAN 3: targeted epoch seeds + warm-up sweeps -----
    h3 = targeted_tests(pairs)
    all_hits += h3
    log("")

    # ---------------- verdict -------------------------------------------
    log("=== VERDICT ===")
    if not all_hits:
        log("  NO MATCH.  Zero exact 128-bit header matches across:")
        log("    - TYPE_3 (310 warm-up): %d seeds x %d headers (K %+d..%+d "
            "per second)" % (s1["seeds"], len(pairs),
                             -K_WINDOW_TYPE3, K_WINDOW_TYPE3))
        log("    - LCG48 (warm-up 0..64): %d seeds x %d headers x 65 W "
            "(K %+d..%+d per second)"
            % (s2["seeds"], len(pairs), -K_WINDOW_LCG48, K_WINDOW_LCG48))
        log("    - targeted epoch seeds x both generators (+ warm-up sweeps "
            "0..%d)" % WARM_SWEEP_MAX)
    else:
        for h in all_hits:
            log("  HIT: %s seed=%d header=%s K(vs capture secs)=%s %s"
                % (h["gen"], h["seed"], h["header"], h["K"],
                   h.get("epoch", "")))
        # a law matching >=2 headers with the SAME K is a solution
        groups: dict[tuple, list] = {}
        for h in all_hits:
            for k in h["K"]:
                groups.setdefault((h["gen"].split("/")[0], h["W"], k),
                                  []).append(h)
        sols = {g: v for g, v in groups.items()
                if len({x["header"] for x in v}) >= 2}
        if sols:
            for g, v in sols.items():
                log("  *** SOLUTION CANDIDATE: gen=%s W=%s K=%d matches %d "
                    "distinct headers ***"
                    % (g[0], g[1], g[2], len({x["header"] for x in v})))
        else:
            log("  (no single (generator, warm-up, K) matches >=2 headers)")

    dt = time.perf_counter() - t_start
    log("")
    log("total wall time: %.1f s" % dt)

    write_result_md(pairs, n_signed, s1, s2, all_hits, dt)
    return all_hits


def write_result_md(pairs, n_signed, s1, s2, hits, dt):
    lines = []
    A = lines.append
    A("# _sub_seedscan — iOS adj9 header PRNG wide seed scan")
    A("")
    A("Run: %s  (python %s, numpy %s, wall %.1f s)"
      % (time.strftime("%Y-%m-%d %H:%M:%S"), sys.version.split()[0],
         np.__version__, dt))
    A("")
    A("## Data extracted")
    A("")
    A("Source: `cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz` — "
      "%d signed requests, **%d unique 16-byte headers** "
      "(ClientBeginRequest, +05:30, floored to unix seconds)."
      % (n_signed, len(pairs)))
    A("")
    A("| approx unix second | reqs | header16 (hex) |")
    A("|---|---|---|")
    for p in pairs:
        A("| %d | %d | `%s` |" % (p["T"], p["reqs"], p["hdr"].hex()))
    A("")
    A("Capture-second span: %d .. %d (%d s).  All %d headers have every word "
      "< 2^31 (consistent with XOR of two 31-bit draws)."
      % (pairs[0]["T"], pairs[-1]["T"], pairs[-1]["T"] - pairs[0]["T"],
         len(pairs)))
    A("")
    A("## Vectorization cross-checks (all PASS, run before any scan)")
    A("")
    A("1. Vectorized TYPE_3 (31xN uint32 state matrix, 30-step MINSTD Schrage "
      "init incl. negative-r[0] branch, 310+8 vectorized feedback steps) vs "
      "`adj9_signer.Random3`: **113 seeds (100 random + edge/epoch cases), "
      "all 8 draws AND 4 XOR words equal.**")
    A("2. Vectorized TYPE_3 header vs `adj9_signer.make_header` on the 9 "
      "genuine ANDROID gold seconds: **9/9 byte-exact**.")
    A("3. Vectorized srand48/lrand48 (48-bit LCG, exact 24/24-bit split "
      "multiply) vs scalar reference: **106 seeds x 72 draws equal**, "
      "XOR words equal for warm-ups 0..64 spot checks.")
    A("4. Scalar arbitrary-warm-up TYPE_3 vs Random3: 20 seeds equal.")
    A("5. End-to-end scan machinery sanity: a planted known Android header "
      "was recovered by the scan at K=0, warm-up 310.")
    A("")
    A("## Scans executed (exact coverage)")
    A("")
    A("| generator | warm-ups | seed law | K window | seeds scanned | "
      "(second,K) header evaluations | candidates prefiltered | exact hits |")
    A("|---|---|---|---|---|---|---|---|")
    A("| bionic TYPE_3 | 310 | second + K | %+.0f..%+.0f | %d | %d | %d | %d |"
      % (-K_WINDOW_TYPE3, K_WINDOW_TYPE3, s1["seeds"],
         len(pairs) * (2 * K_WINDOW_TYPE3 + 1), s1["candidates"],
         len([h for h in hits if h["gen"].startswith("TYPE_3")])))
    A("| srand48/lrand48 | 0..64 | second + K | %+.0f..%+.0f | %d | %d x 65 W "
      "= %d | %d | %d |"
      % (-K_WINDOW_LCG48, K_WINDOW_LCG48, s2["seeds"],
         len(pairs) * (2 * K_WINDOW_LCG48 + 1),
         len(pairs) * (2 * K_WINDOW_LCG48 + 1) * 65, s2["candidates"],
         len([h for h in hits if h["gen"].startswith("LCG48")])))
    A("")
    A("Union seed range TYPE_3: %d..%d (covers K in [%+d,%+d] for every "
      "capture second).  Union seed range LCG48: %d..%d "
      "(K in [%+d,%+d]).  Prefilter = 24-bit Bloom over the %d observed w0 "
      "values (false-positive rate %.2e per test); every candidate "
      "re-verified exactly (all 4 words) with the scalar ground-truth "
      "generator."
      % (pairs[0]["T"] - K_WINDOW_TYPE3, pairs[-1]["T"] + K_WINDOW_TYPE3,
         -K_WINDOW_TYPE3, K_WINDOW_TYPE3,
         pairs[0]["T"] - K_WINDOW_LCG48, pairs[-1]["T"] + K_WINDOW_LCG48,
         -K_WINDOW_LCG48, K_WINDOW_LCG48, len(pairs),
         len(pairs) / (1 << FILTER_BITS)))
    A("")
    A("## Targeted tests (exact seeds, no scan)")
    A("")
    A("For every capture second T: seed = T-978307200 (Apple epoch), "
      "T+2082844800 (1904 epoch), (T*1000)&(2^31-1), (T*1000)&(2^32-1) "
      "against TYPE_3 (310 warm-up) and LCG48 (warm-up 0..64); plus warm-up "
      "sweeps W=0..4096 for TYPE_3 and LCG48 at seed = T and each epoch "
      "seed.  (Exact, vectorized over W.)")
    A("")
    A("## Result")
    A("")
    if not hits:
        A("**NO MATCH.**  Zero exact 4-word (128-bit) header matches "
          "anywhere in:")
        A("")
        A("- bionic TYPE_3 with 310 warm-up, seed = capture_second + K for "
          "all K in [%+d, %+d] — %d seeds, %d (second,K) evaluations per "
          "header."
          % (-K_WINDOW_TYPE3, K_WINDOW_TYPE3, s1["seeds"],
             2 * K_WINDOW_TYPE3 + 1))
        A("- srand48/lrand48 with warm-ups 0..64, seed = capture_second + K "
          "for all K in [%+d, %+d] — %d seeds x 65 warm-ups."
          % (-K_WINDOW_LCG48, K_WINDOW_LCG48, s2["seeds"]))
        A("- targeted Apple/1904/millisecond-epoch seeds (both generators) "
          "and warm-up sweeps 0..4096.")
        A("")
        A("Therefore the iOS header is NOT produced by the bionic TYPE_3 "
          "rand nor by lrand48 under any second-derived seed within "
          "+/-58 days (TYPE_3) / +/-3.2 years (LCG48) of the captures, nor "
          "by any of the targeted epoch conversions.  The iOS PRNG law "
          "remains unidentified; next probes should target generator "
          "FAMILIES outside these two (e.g. xorshift/PCG/xoshiro, iOS "
          "arc4random/ChaCha20-based, Swift/objc RNGs, or a seeded "
          "shuffle-based law like the Android region PRNG).")
    else:
        A("**MATCH(ES) FOUND:**")
        A("")
        A("| generator | warm-up | seed | K vs capture second(s) | header |")
        A("|---|---|---|---|---|")
        for h in hits:
            A("| %s | %d | %d | %s | `%s` |"
              % (h["gen"], h["W"], h["seed"],
                 ", ".join(str(k) for k in h["K"]), h["header"]))
        sols: dict[tuple, set] = {}
        for h in hits:
            for k in h["K"]:
                sols.setdefault((h["gen"].split("/")[0], h["W"], k),
                                set()).add(h["header"])
        multi = {g: v for g, v in sols.items() if len(v) >= 2}
        A("")
        if multi:
            A("**SOLUTION: %s** — matches >=2 headers at the same K."
              % multi)
        else:
            A("Single-header matches only (see table).")
    A("")
    A("## Notes")
    A("")
    A("- Requests in the same capture second can share a header (observed: "
      "header `3be1d83d…` spans capture seconds 1787553341-342), consistent "
      "with the per-second header law.")
    A("- Only this script and `_sub_seedscan_RESULT.md` were written; "
      "`adj9_signer.py` was imported read-only (bytecode writing disabled).")
    A("")

    with open(RESULT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("[WRITE] %s" % RESULT_MD, flush=True)


if __name__ == "__main__":
    main()
