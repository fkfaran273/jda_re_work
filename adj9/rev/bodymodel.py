"""bodymodel.py — measure the exact GF(2) body map for one (descs, second).

A Model is  body = c XOR L(region)  with c the zero-region body and L a
256-input-bit -> 1408-output-bit GF(2) linear map.  Recovering L needs 256
independent sample regions; a random 256x256 GF(2) matrix is singular with
probability ~0.29, so the sampling matrix is checked for invertibility
BEFORE any VM run, and the raw measurements are cached to disk so the
linear algebra can be redone for free.
"""
import hashlib
import json
import os
import random
import struct
import sys
from concurrent.futures import ProcessPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mint_pipeline as M          # noqa: E402

BLOB_WORDS = 48
BODY_WORDS = 44
NBITS = 44 * 32

# (name, desc-slot bi, word index).  bi 0 = d0, 2 = d2, 4 = d4.
ACTIVE = (("W0", 0, 0), ("X", 0, 1), ("T0", 0, 2), ("T1", 0, 3),
          ("F4", 4, 4), ("F5", 4, 5), ("F6", 4, 6), ("S", 2, 0))
NWORD = len(ACTIVE)
NVAR = 32 * NWORD
DESC_POS = {0: 0, 2: 4, 4: 3}
ZERO_REGION = {0: b"\x00" * 144, 2: b"\x00" * 4, 4: b"\x00" * 32}

RANK_MIN = 192          # col(W0) == col(F5) == col(F6)  =>  64-dim kernel


# ---------------------------------------------------------------------------
def _patch(job):
    base_descs, claims, kind, second, patch = job
    if base_descs is None:
        region = dict(ZERO_REGION)
        for (name, bi, w), val in (patch or {}).items():
            region[bi] = region[bi][:4 * w] + val + region[bi][4 * (w + 1):]
        descs, _ = M.build_descriptors(claims, kind, region[0], region[2],
                                       region[4])
    else:
        descs = list(base_descs)
        for bi in (0, 2, 4):
            q = DESC_POS[bi]
            descs[q] = (len(ZERO_REGION[bi]) // 4, descs[q][1], ZERO_REGION[bi])
        for (name, bi, w), val in (patch or {}).items():
            p = DESC_POS[bi]
            d = bytearray(descs[p][2])
            d[4 * w:4 * w + 4] = val
            descs[p] = (len(d) // 4, descs[p][1], bytes(d))
    blob, _ = M.finex_mint(descs, int(second), max_steps=60_000_000)
    return list(struct.unpack(">%dI" % BLOB_WORDS, blob))


# ---------------------------------------------------------------------------
# GF(2)
# ---------------------------------------------------------------------------
def gf2_solve(equations):
    """-> (particular solution, rank) or (None, rank) if inconsistent."""
    piv = {}
    for mask, bit in equations:
        v, b = mask, bit & 1
        while v:
            p = v.bit_length() - 1
            if p in piv:
                pm, pb = piv[p]
                v ^= pm
                b ^= pb
            else:
                piv[p] = (v, b)
                break
        else:
            if b:
                return None, len(piv)
    sol = 0
    for p in sorted(piv):
        v, b = piv[p]
        rest = v & ~(1 << p)
        if b ^ (bin(rest & sol).count("1") & 1):
            sol |= 1 << p
    return sol, len(piv)


def gf2_rank(rows, n):
    piv = {}
    for v in rows:
        while v:
            p = v.bit_length() - 1
            if p in piv:
                v ^= piv[p]
            else:
                piv[p] = v
                break
    return len(piv)


def gf2_inverse_rows(mat, n):
    m = [mat[i] | (1 << (n + i)) for i in range(n)]
    for col in range(n):
        p = None
        for r in range(col, n):
            if (m[r] >> col) & 1:
                p = r
                break
        if p is None:
            return None
        m[col], m[p] = m[p], m[col]
        for r in range(n):
            if r != col and (m[r] >> col) & 1:
                m[r] ^= m[col]
    return [(m[i] >> n) & ((1 << n) - 1) for i in range(n)]


def draw_samples(nsamp, seed):
    """nsamp random region vectors whose sampling matrix is nonsingular."""
    rng = random.Random(seed)
    vecs = []
    while len(vecs) < nsamp:
        v = rng.getrandbits(NVAR)
        if v and v not in vecs:
            vecs.append(v)
        if len(vecs) % 16 == 0 and gf2_rank(vecs, NVAR) < len(vecs):
            vecs.pop()                      # keep the matrix full rank
    return vecs


def bits_of(words):
    out = []
    for w in words:
        for b in range(32):
            out.append((w >> (31 - b)) & 1)
    return out


# ---------------------------------------------------------------------------
class Model:
    __slots__ = ("c", "cols", "second", "kind", "nsamp", "rank")

    def __init__(self, c, cols, second, kind, nsamp):
        self.c, self.cols = c, cols
        self.second, self.kind, self.nsamp = int(second), kind, nsamp
        self.rank = gf2_rank(cols, NVAR)

    # -- measurement ----------------------------------------------------
    @classmethod
    def measure(cls, second, base_descs=None, claims=None, kind="session",
                nsamp=NVAR, workers=16, sample_seed=12345, cache=None,
                progress=False):
        second = int(second)
        vecs = draw_samples(nsamp, sample_seed)
        if gf2_inverse_rows(vecs, NVAR) is None:
            raise ValueError("sampling matrix still singular")
        key = _key(second, base_descs, claims, kind, nsamp, sample_seed)
        raw = None
        if cache and os.path.exists(cache):
            try:
                cand = json.load(open(cache))
                if (cand["key"] == key and len(cand["bodies"]) == nsamp
                        and len(cand["bodies"]) == len(vecs)
                        and cand.get("vecs") == vecs):
                    if not cand.get("c"):
                        # sample bodies are still valid, only the zero-region
                        # constant is missing -> one extra mint repairs it
                        with ProcessPoolExecutor(max_workers=1) as pool:
                            c0 = list(pool.map(
                                _patch,
                                [(base_descs, claims, kind, second, None)]))[0]
                        cand["c"] = c0[4:]
                        print("   recovered cached bodies + constant")
                    raw = cand
            except Exception as e:
                print("   cache reuse failed: %s" % e)
                raw = None
        if raw is None:
            jobs = [(base_descs, claims, kind, second, None)]
            for v in vecs:
                patch = {a: struct.pack(">I", (v >> (32 * n)) & 0xFFFFFFFF)
                         for n, a in enumerate(ACTIVE)}
                jobs.append((base_descs, claims, kind, second, patch))
            with ProcessPoolExecutor(max_workers=workers) as pool:
                res = list(pool.map(_patch, jobs))
            raw = {"key": key, "second": second, "kind": kind, "nsamp": nsamp,
                   "vecs": vecs, "c": res[0][4:],
                   "bodies": [r[4:] for r in res[1:]]}
        if cache:
            try:
                json.dump(raw, open(cache, "w"))
            except Exception as e:            # cache is an optimization only
                print("   cache write failed: %s" % e)
        if progress:
            print("   measured %d samples" % nsamp)
        return cls.from_raw(raw, kind)

    @classmethod
    def from_raw(cls, raw, kind=None):
        vecs = raw["vecs"]
        B = [bits_of(b) for b in raw["bodies"]]
        inv = gf2_inverse_rows(vecs, NVAR)
        cols = []
        for j in range(NBITS):
            bvec = 0
            for k in range(len(vecs)):
                if B[k][j]:
                    bvec ^= inv[k]
            cols.append(bvec)
        return cls(raw["c"], cols, raw["second"], kind or raw.get("kind"),
                   raw["nsamp"])

    # -- use ------------------------------------------------------------
    def predict(self, words):
        body = list(self.c)
        for n, (name, _bi, _w) in enumerate(ACTIVE):
            v = words.get(name, 0) & 0xFFFFFFFF
            if not v:
                continue
            for b in range(32):
                if (v >> (31 - b)) & 1:
                    m = self.cols[32 * n + b]
                    for j in range(NBITS):
                        if (m >> j) & 1:
                            body[j >> 5] ^= 1 << (31 - (j & 31))
        return body

    def solve(self, body):
        eqs = []
        for j in range(BODY_WORDS):
            d = (body[j] ^ self.c[j]) & 0xFFFFFFFF
            for b in range(32):
                m = 0
                for n in range(NWORD):
                    if (self.cols[32 * n + b] >> j) & 1:
                        m |= 1 << (32 * n + b)
                if m:
                    eqs.append((m, (d >> (31 - b)) & 1))
        sol, rank = gf2_solve(eqs)
        if sol is None or rank < RANK_MIN:
            return None
        out = {a[0]: (sol >> (32 * n)) & 0xFFFFFFFF for n, a in enumerate(ACTIVE)}
        out["_rank"] = rank
        return out


def _key(second, base_descs, claims, kind, nsamp, sample_seed):
    h = hashlib.sha1()
    h.update(("%d|%s|%d|%d|" % (second, kind, nsamp, sample_seed)).encode())
    if base_descs is None:
        h.update(json.dumps(claims, sort_keys=True).encode())
    else:
        for lendl, tag, data in base_descs:
            h.update(("%d|%d|%s|" % (lendl, tag, bytes(data).hex())).encode())
    return h.hexdigest()
