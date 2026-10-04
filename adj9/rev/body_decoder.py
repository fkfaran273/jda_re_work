"""body_decoder.py — the adj9 VM body decoder (v2, 2026-09-27).

Recovers the descriptor region (d0[36], d2, d4[8]) from a 192-B adj9
signature blob given the claims descriptor bytes and the signing second.

STRUCTURE (verified on corpus row 7 via fin_vm2 emit wire dumps, 2026-09-27):

  * The VM builds a 144-byte RECORD on its working stream (0x5450001000,
    first-write offsets 1134..1277):

        [0:3)     01 00 08                       flags
        [3:19)    d0[0..3], each word rev16'd,
                  stored little-endian per word   the head (16 B)
        [19]      02
        [20:24)   d2 little-endian  = THE SEED S  (native memory form)
        [24]      03
        [25:45)   d9 = APK cert SHA-1
        [45]      04
        [46:78)   32-byte block, hash-like in (head, S, d4[4]...)
        [78]      05
        [79:111)  SHA256("")
        [111:114) 06 01 07
        [114:128) 00 * 14
        [128:130) 2 bytes, d4[4]-dependent (00 00 on the corpus rows)
        [130:144) 0e * 14

  * body[0:144) (blob words 4..39) = WHITEN(record) — a BYTE-GRANULAR
    GF(2)-AFFINE map (the queue program mixes with eor/swap/copy only):

        body[m] = XOR_j A[m][j] * var[j]  XOR  c[m]

    where var = the 54 variable record bytes (head 16, d2le 4, block 32,
    tail 2) and A/c are fixed for a given (claims, second).  NOT word-linear
    in the region (the block is a hash of region words — that is what broke
    the earlier word-level GF(2) attempt, bodymodel.py).

  * body[144:176) (blob words 40..47) is a 32-B digest; it is not needed for
    the decode — the remint check covers it.

  * A and c are MEASURED with 10-12 probe runs of the proven forward encoder
    (fin_vm2.FinEx) at the TARGET (claims, second) using random F.py regions;
    each probe's record is read straight off the run's emit wire log.
    body words 40..47 are ignored.

  * The target's 54 variable bytes are recovered per bit-plane by
    over-determined GF(2) elimination (8 systems of 144 equations, 54
    unknowns).  S falls out at [20:24); d0[0..3] at [3:19); the remaining
    region words are reconstructed with F.py from S = seed and the head
    phase (HEAD_FIRST / HEAD_RESIGN disambiguated by the recovered head).

  * Self-checks: in-sample probe prediction must be 144/144 bytes on every
    probe; the solved record must reproduce every constant byte; the remint
    must reproduce the full 192-B blob.

Usage:
    dec = BodyDecoder(descs_base, second, workers=6)   # probes run here
    res = dec.decode(blob)                             # dict with record/S/head
    region = dec.region_from(res)                      # (d0[36], d2, d4[8]) words
"""
import hashlib
import json
import os
import struct
import sys
import time
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fin_vm2 import FinEx                     # noqa: E402

MAIN = 0x5450001000        # VM working stream carrying the record
SINK = 0x5500000000        # blob stream
REC_BASE = 620             # section top of the record area
REC_OFF = 514              # record start within the section (abs. off 1134)
REC_N = 144

# variable record-byte positions
VAR_POS = (list(range(3, 19)) + list(range(20, 24)) +
           list(range(46, 78)) + [128, 129])
NV = len(VAR_POS)          # 54

# constant positions -> expected bytes (checked after the solve)
SHA0 = hashlib.sha256(b"").digest()
CONST_CHECKS = (
    ((0, 3), bytes.fromhex("010008")),
    ((19, 20), b"\x02"),
    ((24, 25), b"\x03"),
    ((45, 46), b"\x04"),
    ((78, 79), b"\x05"),
    ((79, 111), SHA0),
    ((111, 114), bytes.fromhex("060107")),
    ((114, 128), b"\x00" * 14),
    ((130, 144), b"\x0e" * 14),
)

VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
REGION_DESC_IDX = {0: 0, 2: 4, 4: 3}       # desc-bi -> VA_ORDER position


# ---------------------------------------------------------------------------
# probe worker
# ---------------------------------------------------------------------------
def _probe_run(job):
    """Run FinEx once; return (record144, body144, steps, status, seconds)."""
    descs, second = job
    ex = FinEx(second, descs)
    ex.__dict__["_emit_full"] = []       # (pc, sva, top, n, v) per EMIT
    t0 = time.time()
    st = ex.run(max_steps=60_000_000)
    ef = ex.__dict__["_emit_full"]
    rec = {}
    for (pc, sva, top, n, v) in ef:
        if (sva & 0xFFFFFFFFFFFF) == MAIN:
            o = top + n
            if REC_BASE + REC_OFF <= o < REC_BASE + REC_OFF + REC_N \
                    and o not in rec:
                rec[o] = v & 0xFF
    if len(rec) != REC_N:
        raise RuntimeError("probe record incomplete: %d/144 (status %s)"
                           % (len(rec), st))
    record = bytes(rec[REC_BASE + REC_OFF + i] for i in range(REC_N))
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n)] = v & 0xFFFFFFFF
    body = b"".join(struct.pack(">I", last.get((SINK, k), 0))
                    for k in range(4, 40))
    return record, body, ex.steps, st, time.time() - t0


# ---------------------------------------------------------------------------
# GF(2) helpers
# ---------------------------------------------------------------------------
def _gauss(rows, ncols):
    """rows: list of (mask, rhs).  Returns (rref, rank, pivot cols,
    n_inconsistent)."""
    rows = list(rows)
    pivots = []
    r = 0
    incons = 0
    for c in range(ncols):
        bit = 1 << c
        p = None
        for i in range(r, len(rows)):
            if rows[i][0] & bit:
                p = i
                break
        if p is None:
            continue
        rows[r], rows[p] = rows[p], rows[r]
        for i in range(len(rows)):
            if i != r and (rows[i][0] & bit):
                rows[i] = (rows[i][0] ^ rows[r][0], rows[i][1] ^ rows[r][1])
        pivots.append(c)
        r += 1
        if r == len(rows):
            break
    for mask, rhs in rows[r:]:
        if mask == 0 and rhs:
            incons += 1
    return rows, r, pivots, incons


# ---------------------------------------------------------------------------
# the decoder
# ---------------------------------------------------------------------------
class BodyDecoder:
    def __init__(self, descs_base, second, n_probes=12, verbose=True,
                 probe_seed=0x5EED, workers=6, pool=None, probes=None):
        """descs_base: 11 (len_dw, tag, data) triples in VA order with
        PLACEHOLDER d0/d2/d4 (replaced by the probes); everything else
        (claims #10, cert #9, #8, #7, #5/#6) must be the target's values.
        `probes` may pass pre-measured [(record, body), ...] to skip runs.
        """
        self.descs_base = [list(t) for t in descs_base]
        self.second = int(second)
        self.verbose = verbose
        self.n_probes = n_probes
        self._probe_seed = probe_seed
        self._workers = workers
        self.A = None              # A[m] = 54-bit mask over VAR positions
        self.c = None              # c[m] byte
        self.probe_meta = []
        self._var0 = None          # probe 0's variable bytes
        if probes is None:
            probes = self._run_probes()
        self._measure(probes)

    # -- probing -----------------------------------------------------------
    def _make_probe_descs(self, rng):
        import F as Fmod
        V = rng.getrandbits(31)
        pid = rng.randrange(1, 0x8000)
        d0w, d2w, d4w = Fmod.region(V, pid, 0, head=Fmod.HEAD_FIRST)
        d0 = b"".join(struct.pack(">I", w) for w in d0w)
        d2 = struct.pack(">I", d2w)
        d4 = b"".join(struct.pack(">I", w) for w in d4w)
        descs = [list(t) for t in self.descs_base]
        for bi, data in ((0, d0), (2, d2), (4, d4)):
            i = VA_ORDER.index(bi)
            descs[i][2] = data
            descs[i][0] = len(data) // 4
        return [tuple(t) for t in descs]

    def _run_probes(self):
        import random
        rng = random.Random(self._probe_seed)
        jobs = [(self._make_probe_descs(rng), self.second)
                for _ in range(self.n_probes)]
        t0 = time.time()
        if self._workers and self._workers > 1:
            with Pool(self._workers) as p:
                res = p.map(_probe_run, jobs)
        else:
            res = [_probe_run(j) for j in jobs]
        self.probe_meta = [{"steps": steps, "status": st, "sec": round(dt, 1)}
                           for (_, _, steps, st, dt) in res]
        if self.verbose:
            print("[decoder] %d probes in %.0fs (status %s)"
                  % (len(res), time.time() - t0,
                     sorted(set(m["status"] for m in self.probe_meta))),
                  flush=True)
        return [(r, b) for (r, b, _, _, _) in res]

    # -- measurement -------------------------------------------------------
    def _measure(self, probes):
        recs = [r for (r, _) in probes]
        bods = [b for (_, b) in probes]
        self._rec0 = recs[0]
        self.probe_records = recs
        self.probe_bodies = bods
        Vm = [[rec[p] for p in VAR_POS] for rec in recs]
        self._var0 = Vm[0]

        # A[m]: solve from deltas vs probe 0.  For each probe p and bit b:
        #   XOR_j A[m][j] * (var_p[j] ^ var_0[j])_b = (body_p[m]^body_0[m])_b
        A = [None] * REC_N
        A_rank = REC_N
        A_incons = 0
        for m in range(REC_N):
            rows = []
            for p in range(1, len(recs)):
                dv = [(Vm[p][j] ^ Vm[0][j]) for j in range(NV)]
                db = bods[p][m] ^ bods[0][m]
                for b in range(8):
                    mask = 0
                    for j in range(NV):
                        if (dv[j] >> b) & 1:
                            mask |= 1 << j
                    rows.append((mask, (db >> b) & 1))
            rref, rank, piv, incons = _gauss(rows, NV)
            A_incons += incons
            A_rank = min(A_rank, rank)
            x = 0
            for ci, cnum in enumerate(piv):
                if rref[ci][1]:
                    x |= 1 << cnum
            A[m] = x
        self.A = A
        self.A_rank = A_rank
        self.A_incons = A_incons

        # c[m] = body_0[m] ^ A[m].var_0
        self.c = bytes(bods[0][m] ^ _applyA(A[m], Vm[0])
                       for m in range(REC_N))

        # in-sample check: predict every probe body from its record
        bad = 0
        for p in range(len(recs)):
            pred = self.predict_body(Vm[p])
            bad += sum(1 for m in range(REC_N) if pred[m] != bods[p][m])
        self.insample_bad = bad
        if self.verbose:
            print("[decoder] A rank %d/%d inconsist=%d in-sample bad %d/%d"
                  % (A_rank, NV, A_incons, bad, REC_N * len(recs)), flush=True)

    def predict_body(self, var_bytes):
        """var_bytes: list of NV bytes -> predicted 144-B body."""
        return bytes(_applyA(self.A[m], var_bytes) ^ self.c[m]
                     for m in range(REC_N))

    # -- decoding ----------------------------------------------------------
    def decode(self, blob):
        """blob: 192-B signature.  Returns dict with the recovered record,
        S (the seed), head and validity checks."""
        blob = bytes(blob)
        body = blob[16:160]
        # per bit-plane solve:  XOR_j A[m][j]*x_j = body[m]_b ^ c[m]_b
        var = [0] * NV
        total_rank = 0
        total_incons = 0
        for b in range(8):
            rows = []
            for m in range(REC_N):
                d = (body[m] ^ self.c[m]) & 0xFFFFFFFF
                rhs = (d >> b) & 1
                rows.append((self.A[m], rhs))
            rref, rank, piv, incons = _gauss(rows, NV)
            total_rank = max(total_rank, rank)
            total_incons += incons
            x = 0
            for ci, cnum in enumerate(piv):
                if rref[ci][1]:
                    x |= 1 << cnum
            for j in range(NV):
                if (x >> j) & 1:
                    var[j] |= 1 << b
        rec = bytearray(self._record_with_zero_vars())
        for j, p in enumerate(VAR_POS):
            rec[p] = var[j]
        rec = bytes(rec)
        consts_ok = all(rec[a:b] == want for (a, b), want in CONST_CHECKS)
        seed = int.from_bytes(rec[20:24], "little")      # native seed S
        d2w = int.from_bytes(rec[20:24], "big")          # d2 BE descriptor word
        head = rec[3:19]
        out = {
            "record": rec,
            "seed": seed,
            "S": seed,
            "d2": d2w,
            "head": head.hex(),
            "block": rec[46:78].hex(),
            "tail2": rec[128:130].hex(),
            "rank": total_rank,
            "inconsistent": total_incons,
            "consts_ok": consts_ok,
        }
        return out

    def _record_with_zero_vars(self):
        rec = bytearray(self._rec0)
        for p in VAR_POS:
            rec[p] = 0
        return bytes(rec)

    # -- region reconstruction --------------------------------------------
    def region_from(self, dec):
        """decoded dict -> (d0w[36], d2w, d4w[8]) words via F.py, or None
        with `why` set if the head phase cannot be matched."""
        import F as Fmod
        seed = dec["seed"]
        d4w = Fmod._d4_words(seed)
        for name, phase in (("HEAD_FIRST", Fmod.HEAD_FIRST),
                            ("HEAD_RESIGN", Fmod.HEAD_RESIGN)):
            d0w = Fmod._d0_words(d4w, head=phase)
            head = b"".join(struct.pack("<I",
                                        ((w & 0xFFFF) << 16) | (w >> 16))
                            for w in d0w[:4])
            if head == dec["head"]:
                d2w = int.from_bytes(struct.pack("<I", seed), "big")
                return {"d0": d0w, "d2": d2w, "d4": d4w, "phase": name}
        return None


def _applyA(rowmask, varvals):
    acc = 0
    mm = rowmask
    while mm:
        b = mm & -mm
        j = b.bit_length() - 1
        mm ^= b
        acc ^= varvals[j]
    return acc
