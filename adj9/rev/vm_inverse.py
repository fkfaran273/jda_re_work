"""vm_inverse.py — the INVERSE of the adj9 signature VM (blob -> region).

Given a 192-B adj9 signature blob + the claims descriptor bytes (#10) + the
signing second, recover the per-signing region (d0[36], d2, d4[8]).

MECHANISM (all measured 2026-09-28, corpus row 7 + differential probes):

  1. The VM builds a 144-byte RECORD on the MAIN stream (0x5450001000) at
     flat offs [1134..1278) (record builder site 0x119538, bytes written in
     REVERSE order):

        [0:3)     01 00 08
        [3:19)    head = d0[0..3]  (each word rev16'd, LE-packed = native)
        [19]      02
        [20:24)   d2 little-endian  = the native 32-bit seed S
        [24]      03
        [25:45)   d9 = APK cert SHA-1 (constant)
        [45]      04
        [46:78)   32-B block (region-derived hash-like material)
        [78]      05
        [79:111)  SHA256("")
        [111:114) 06 01 07
        [114:128) 00 * 14
        [128:130) tail2 (d4[4]-dependent; 00 00 on every corpus row)
        [130:144) 0e * 14

  2. The whitening that turns the record into blob body bytes 0..143 is a
     FIXED PIPELINE of wire ops (EMIT/LENQ on MAIN) whose SCHEDULE — the
     exact (site pc, position, tap positions) sequence — is REGION-
     INDEPENDENT for a given (claims, second): two runs with completely
     different regions produce the IDENTICAL event sequence (21,965 events,
     verified).  The region bytes enter the pipeline ONLY through the
     record-build writes; every other value op is byte-local:
         v_new = F(cur, taps)      (taps = LENQ reads of other positions)
  3. Site laws (fitted from 4-template differential runs, row 7):
       0x111c68  v = cur ^ 0x55 ^ KB[481 + p mod 16]     (final sweep; KB =
                 the region-independent 37-B chunk at [1080..1117))
       0x111f70  v = S[cur + 621] ^ 0x55                 (SELF-KEYED
                 substitution: the byte's own value selects the tap)
       0x10a228  v = cur ^ rawheader[p mod 16]           (Random3 key XOR)
       0x109f9c  144-instance memmove, window shift -17  (unit-undone)
       plus xc/xct/ac/act algebraic sites and xt copy sites.

  INVERSION (this module):
     * run the forward VM 3-4 times at the TARGET (claims, second) with
       throwaway regions -> the schedule; fit each EMIT instance's
       (op, K) from the (cur, taps, v) triples across templates, with the
       site's self-read (LENQ of its own position) dropped as redundant;
     * replay the schedule BACKWARD on the target blob: state starts as the
       blob body bytes at the record positions; every EMIT instance is
       undone with its fitted inverse; memmove runs are undone as units;
       self-keyed substitutions are inverted by 256-candidate enumeration;
     * the result is the raw record -> S = record[20:24) (LE) ->
       d4 = F._d4_words(S), d0 = F._d0_words(d4, head phase matched against
       the recovered head), d2 = BE(S);
     * self-checks: recovered raw header == Random3(second), record
       constants (d9, SHA256(""), markers), full remint == the blob.

  STATUS (2026-09-28, corpus row 7): schedule + op fitting covers 11,008 of
  14,670 pipeline events (75%): xct 3553, xc 2794, skt 2013, c 1333, xt
  1283, act 32.  The remaining 3,662 ERR events resist unary-transformed
  xor/add/sub tree fits over ALL their visible inputs — they mix the bytes
  with a 32-BIT word-level state carried through the value queues
  (measured: 20,306 32-bit PUSH/POP pairs on queue 0x5450003000; e.g.
  POP 0x52B23A4A / PUSH 0xF7E2F744 at site 0x113158).  Those sites
  (0x10d0ec / 0x110e30 / 0x10a5fc / 0x10fbf4 diagonal sweeps; the
  0x113158 / 0x113818 / 0x112b60 / 0x109504 hash-state writers; the
  0x10c4d8 / 0x10de2c family) form the whitening's word-hash stage.  The
  backward walk stops there, so the FULL region decode is BLOCKED on that
  one stage and corpus validation is 0/6 — not 6/6.  Everything else
  (record layout, fitted inverses, self-checks, region reconstruction,
  remint oracle) is in place and waits only on that stage.

  The region words that never reach the blob (d0[4..35], d4[0..3,5..7] —
  dead inputs, flip-tested 0/48) are reconstructed from S by the F.py laws
  (verified 10/10 on the genuine corpus).

CLI:
  python vm_inverse.py row7                 decode corpus row 7 end-to-end
  python vm_inverse.py corpus [0,1,4,5,6,7] corpus validation (default all 6)
  python vm_inverse.py winners              decode the 6 genuine winning blobs

Nothing existing is modified; fin_vm2/vm_final/mint_pipeline are imported.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import random
import struct
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fin_vm2 import FinEx                                  # noqa: E402
import F as FREG                                           # noqa: E402
from header_gen import make_header                         # noqa: E402

MAIN = 0x5450001000          # working stream carrying the record
SINK = 0x5500000000          # blob stream
M48 = 0xFFFFFFFFFFFF         # stream VA tag mask

REC_TOP = 1134               # flat offs of record[0] on MAIN
REC_N = 144
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
SHA0 = hashlib.sha256(b"").digest()

REC_CONST_CHECKS = (
    (0, 3, b"\x01\x00\x08"),
    (19, 20, b"\x02"),
    (24, 25, b"\x03"),
    (25, 45, D9),
    (45, 46, b"\x04"),
    (78, 79, b"\x05"),
    (79, 111, SHA0),
    (111, 114, b"\x06\x01\x07"),
    (114, 128, b"\x00" * 14),
    (130, 144, b"\x0e" * 14),
)

VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
N_TEMPLATES = 4              # forward runs used to fit the per-event ops


# ---------------------------------------------------------------------------
# capture: one forward run -> event schedule + record + body
# ---------------------------------------------------------------------------
def _region_descs(base_descs, rng):
    """base descs with a random F.py region swapped into #0/#2/#4."""
    V = rng.getrandbits(31)
    pid = rng.randrange(1, 0x8000)
    d0w, d2w, d4w = FREG.region(V, pid, 0, head=FREG.HEAD_FIRST)
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d2 = struct.pack(">I", d2w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    ds = [list(t) for t in base_descs]
    for bi, data in ((0, d0), (2, d2), (4, d4)):
        i = VA_ORDER.index(bi)
        ds[i][2] = data
        ds[i][0] = len(data) // 4
    return [tuple(t) for t in ds]


def capture(second, descs, max_steps=60_000_000):
    """One forward FinEx run.

    Returns dict:
      events : [(kind, pc, abs, val)] for MAIN EMIT/LENQ (whole run, order)
      record : the raw record bytes (first write per record position)
      body   : 144 final bytes at the record positions
      blob   : the 192-B blob this run produced
    """
    ex = FinEx(int(second), descs)
    ex.__dict__["_wire_log"] = []
    t0 = time.time()
    st = ex.run(max_steps=max_steps)
    dt = time.time() - t0
    events = []
    fw = {}
    lw = {}
    for ev in ex.__dict__["_wire_log"]:
        if (ev[2] & M48) != MAIN:
            continue
        o = ev[3] + ev[4]
        v = ev[5] & 0xFF
        events.append((ev[0], ev[1], o, v))
        if ev[0] == "E":
            if o not in fw:
                fw[o] = v
            lw[o] = v
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & M48, n)] = v & 0xFFFFFFFF
    blob = b"".join(struct.pack(">I", last.get((SINK, k), 0))
                    for k in range(48))
    record = bytes(fw.get(REC_TOP + i, 0) for i in range(REC_N))
    body = bytes(lw.get(REC_TOP + i, 0) for i in range(REC_N))
    return {"events": events, "record": record, "body": body,
            "blob": blob, "status": st, "sec": dt}


# ---------------------------------------------------------------------------
# replay + fitting
# ---------------------------------------------------------------------------
def replay(events):
    """Forward replay of the MAIN event list.

    Returns per-E instances (idx, abs, cur, taps, v):
      cur  = the pre-write value at the written position (inline)
      taps = [(abs, val), ...] LENQ reads since the previous EMIT, with the
      site's SELF-read (abs == the written position) dropped (redundant: it
      equals cur).
    """
    state = {}
    insts = []
    qwin = []
    for k, (kind, pc, o, v) in enumerate(events):
        if kind == "Q":
            if o not in {q[0] for q in qwin}:
                qwin.append((o, state.get(o, 0)))
        else:
            cur = state.get(o, 0)
            taps = tuple((a, b) for (a, b) in qwin if a != o)
            insts.append((k, o, cur, taps, v))
            state[o] = v
            qwin = []
    return insts


def _x_of(t):
    r = 0
    for _, tv in t:
        r ^= tv
    return r


def _s_of(t):
    return sum(tv for _, tv in t) & 0xFF


def _fit_one(samples):
    """Fit one EMIT instance from >=2 template samples.

    samples: [(cur, taps, v), ...] (cur = pre-write value, inline).

    Returns (op, K, extra):
      fixed taps (positions equal across templates):
        xc   v = cur ^ K
        xct  v = cur ^ xor(taps) ^ K
        ac   v = (cur + K) & 0xFF
        act  v = (cur + sum(taps) + K) & 0xFF
        xt   v = xor(taps) ^ K                (destroys cur)
        c    v = taps[0]                      (destroys cur; copy)
      one varying tap at index j whose position == cur + D (D constant):
        skx  v = cur ^ tapval ^ xor(others) ^ K     (self-keyed)
        ska  v = (cur + tapval + sum(others) + K)   (self-keyed)
      extra = (j, D, n_others) for self-keyed ops.
    """
    if not samples:
        return None, None, None
    ntp = {len(t) for (_, t, _) in samples}
    if len(ntp) != 1:
        return None, None, None
    ntap = ntp.pop()

    def ks(fn):
        return {fn(c, t, v) & 0xFF for (c, t, v) in samples}

    if ntap == 0:
        kk = ks(lambda c, t, v: c ^ v)
        if len(kk) == 1:
            return "xc", kk.pop(), None
        kk = ks(lambda c, t, v: (c - v) & 0xFF)
        if len(kk) == 1:
            return "ac", kk.pop(), None
        return None, None, None
    # tap positions constant across templates?
    pos_const = all(len({t[j][0] for (_, t, _) in samples}) == 1
                    for j in range(ntap))
    if pos_const:
        varying = len({(c, t, v) for (c, t, v) in samples}) > 1
        if varying and all(t and t[0][1] == v for (_, t, v) in samples):
            return "c", 0, None
        kk = ks(lambda c, t, v: c ^ v)
        if len(kk) == 1 and \
                len({(tuple(b for (_, b) in t)) for (_, t, _) in samples}) > 1:
            # taps vary but v == cur ^ K regardless -> taps unused
            return "xc", kk.pop(), None
        kk = ks(lambda c, t, v: c ^ _x_of(t) ^ v)
        if len(kk) == 1:
            return "xct", kk.pop(), None
        kk = ks(lambda c, t, v: (c - v) & 0xFF)
        if len(kk) == 1:
            return "ac", kk.pop(), None
        kk = ks(lambda c, t, v: (c + _s_of(t) - v) & 0xFF)
        if len(kk) == 1:
            return "act", kk.pop(), None
        kk = ks(lambda c, t, v: _x_of(t) ^ v)
        if len(kk) == 1:
            return "xt", kk.pop(), None
        return None, None, None
    var_idx = [j for j in range(ntap)
               if len({t[j][0] for (_, t, _) in samples}) > 1]
    if len(var_idx) != 1:
        return None, None, None
    j = var_idx[0]
    deltas = {t[j][0] - c for (c, t, _) in samples}
    if len(deltas) != 1:
        return None, None, None
    D = deltas.pop()
    others_pos = tuple(aa for jj, (aa, _) in enumerate(samples[0][1])
                       if jj != j)
    kk = set()
    ka = set()
    kt = set()
    kta = set()
    for (c, t, v) in samples:
        others = [b for jj, (_, b) in enumerate(t) if jj != j]
        ox = 0
        for b in others:
            ox ^= b
        tv = t[j][1]
        kk.add(v ^ c ^ tv ^ ox)
        ka.add((v - c - tv - sum(others)) & 0xFF)
        kt.add(v ^ tv)
        kta.add((v - tv) & 0xFF)
    if len(kt) == 1:
        return "skt", kt.pop(), (j, D, others_pos)
    if len(kk) == 1:
        return "skx", kk.pop(), (j, D, others_pos)
    if len(ka) == 1:
        return "ska", ka.pop(), (j, D, others_pos)
    if len(kta) == 1:
        return "skta", kta.pop(), (j, D, others_pos)
    return None, None, None


SELFKEY_OPS = ("skx", "ska", "skt", "skta")


def fit_ops(templates):
    """templates: list of capture dicts (same claims+second, diff regions).

    Returns (insts, stats, unresolved):
      insts[k] = (abs, op, K, tap_positions, extra) for the k-th EMIT
      (schedule order); op 'ERR' marks instances the fit could not pin down.
    """
    reps = [replay(t["events"]) for t in templates]
    n = min(len(r) for r in reps)
    insts = []
    stats = defaultdict(int)
    unresolved = []
    for k in range(n):
        samples = []
        tappos = None
        okinst = True
        for r in reps:
            idx, o, cur, taps, v = r[k]
            if tappos is None:
                tappos = tuple(a for (a, _) in taps)
            samples.append((cur, taps, v))
        op, K, extra = _fit_one(samples)
        if op is None:
            stats["unresolved"] += 1
            unresolved.append((k, reps[0][k]))
            insts.append((reps[0][k][1], "ERR", 0, tappos or (), None))
            continue
        stats[op] += 1
        tps = tuple(a for (a, _) in reps[0][k][3])
        insts.append((reps[0][k][1], op, K, tps, extra))
    return insts, dict(stats), unresolved


def trim_schedule(insts):
    """Keep the pipeline from the first write to a record position onward."""
    first = None
    for k, inst in enumerate(insts):
        if REC_TOP <= inst[0] < REC_TOP + REC_N:
            first = k
            break
    if first is None:
        raise RuntimeError("no record write found in schedule")
    return first, insts[first:]


def find_runs(insts):
    """Maximal runs of consecutive same-pc EMITs.

    Returns [(start, end, pc)] (end exclusive)."""
    runs = []
    s = 0
    for k in range(1, len(insts) + 1):
        if k == len(insts) or insts[k][0] != insts[s][0]:
            runs.append((s, k, insts[s][0]))
            s = k
    return runs


def D_ok(insts, s, e):
    """All instances in the run have uniform target stride 1 and a tap
    (a linear memmove)."""
    os_ = [insts[j][0] for j in range(s, e)]
    if any(o2 - o1 != 1 for o1, o2 in zip(os_, os_[1:])):
        return False
    for j in range(s, e):
        if not insts[j][3]:
            return False
    return True


def backward(blob, insts, known_init=None, verbose=False):
    """Undo the whitening pipeline on a target blob.

    blob: 192-B signature.  insts: fitted, trimmed schedule, each element
    (abs, op, K, tap_positions, extra).

    Returns (record144, header16, report).
    """
    body = blob[16:160]
    state = {}
    for p in range(REC_N):
        state[REC_TOP + p] = body[p]
    if known_init:
        for o, v in known_init.items():
            state[o] = v

    runs = find_runs(insts)
    run_end = {}
    for (s, e, pc) in runs:
        run_end[s] = e

    def S(x):
        v = state.get(x)
        return 0 if v is None else v

    minundone = {}        # position -> smallest undone write index
    skipped = []
    rec = [None] * REC_N
    firstw = {}
    for kk, inst in enumerate(insts):
        if REC_TOP <= inst[0] < REC_TOP + REC_N and \
                inst[0] - REC_TOP not in firstw:
            firstw[inst[0] - REC_TOP] = kk

    def apply(k):
        """Try to undo event k. Returns True if applied."""
        o, op, K, taps, extra = insts[k]
        v = state.get(o)
        if v is None:
            skipped.append((k, o, op, "target-unknown"))
            return True
        p = o - REC_TOP
        if o in firstw and firstw[p] == k and rec[p] is None:
            rec[p] = v          # the record builder's own write
        if op in SELFKEY_OPS:
            j, D, other_pos = extra
            ov = []
            for t in other_pos:
                x = state.get(t)
                if x is None:
                    return False
                ov.append(x)
            ox = 0
            for x in ov:
                ox ^= x
            so = sum(ov) & 0xFF
            cands = []
            if op in ("skt", "skta"):
                tgt = (v ^ K) if op == "skt" else ((v - K) & 0xFF)
                for c in range(256):
                    if S(c + D) == tgt:
                        cands.append(c)
            else:
                for c in range(256):
                    if op == "skx":
                        if ((c ^ S(c + D) ^ ox ^ K) & 0xFF) == v:
                            cands.append(c)
                    else:
                        if ((c + S(c + D) + so + K) & 0xFF) == v:
                            cands.append(c)
            if len(cands) == 0:
                skipped.append((k, o, op, "no-candidate"))
                return True
            if len(cands) > 1:
                return False
            state[o] = cands[0]
            minundone[o] = min(minundone.get(o, k), k)
            return True
        tv = []
        for t in taps:
            x = state.get(t)
            if x is None:
                skipped.append((k, o, op, "tap-unknown:%d" % t))
                return True
            tv.append(x)
        if op == "xc":
            cur = v ^ K
        elif op == "xct":
            cur = v ^ K ^ _x_of(tv)
        elif op == "ac":
            cur = (v - K) & 0xFF
        elif op == "act":
            cur = (v - K - _s_of(tv)) & 0xFF
        else:
            cur = None      # destroying op: repainted by earlier writes
        state[o] = cur
        minundone[o] = min(minundone.get(o, k), k)
        return True

    k = len(insts) - 1
    while k >= 0:
        e = run_end.get(k)
        if e is not None and e - k > 1 and insts[k][1] == "c" and \
                D_ok(insts, k, e):
            # ---- memmove run: undo as a unit ----
            D = insts[k][3][0] - insts[k][0]
            post = {insts[j][0]: state.get(insts[j][0])
                    for j in range(k, e)}
            ok = True
            for j in range(k, e):
                if post[insts[j][0]] is None:
                    ok = False
            if ok:
                for j in range(k, e):
                    oj = insts[j][0]
                    state[oj + D] = post[oj]
                    minundone[oj + D] = min(minundone.get(oj + D, k), k)
                dsts = {insts[j][0] + D for j in range(k, e)}
                for j in range(k, e):
                    oj = insts[j][0]
                    if oj not in dsts:
                        state[oj] = None
                        minundone[oj] = min(minundone.get(oj, k), k)
                k = k - 1
                continue
        apply(k)
        k -= 1

    # ---- fixpoint: retry deferred (skipped) and pending events ----
    for _round in range(8):
        retry = [kk for (kk, o, op, why) in skipped]
        skipped = []
        progressed = False
        for kk in sorted(set(retry), reverse=True):
            o, op, K, taps, extra = insts[kk]
            mu = minundone.get(o)
            if mu is not None and kk > mu:
                skipped.append((kk, o, op, "order"))
                continue
            before = state.get(o)
            if apply(kk):
                progressed = True
            else:
                skipped.append((kk, o, op, "ambiguous"))
        if not progressed:
            break

    recb = bytes(rec[p] if rec[p] is not None else (state.get(REC_TOP + p)
                                                    or 0)
                 for p in range(REC_N))
    hdr = bytes(state.get(1117 + p) or 0 for p in range(16))
    rep = {"skipped": skipped}
    return recb, hdr, rep


def region_from_record(rec):
    """record144 -> dict(d0, d2, d4, phase, seed) via the F.py laws."""
    seed = int.from_bytes(rec[20:24], "little")
    head = rec[3:19]
    d4w = FREG._d4_words(seed)
    for name, phase in (("HEAD_FIRST", FREG.HEAD_FIRST),
                        ("HEAD_RESIGN", FREG.HEAD_RESIGN)):
        d0w = FREG._d0_words(d4w, head=phase)
        hw = b"".join(struct.pack("<I", ((w & 0xFFFF) << 16) | (w >> 16))
                      for w in d0w[:4])
        if hw == head:
            d2w = int.from_bytes(struct.pack("<I", seed), "big")
            return {"d0": list(d0w), "d2": d2w, "d4": list(d4w),
                    "phase": name, "seed": seed}
    return {"d0": None, "d2": None, "d4": None, "phase": None,
            "seed": seed, "head": head.hex()}


def record_checks(rec, hdr=None, second=None):
    out = {"consts_ok": all(rec[a:b] == want
                            for (a, b, want) in REC_CONST_CHECKS)}
    if second is not None and hdr is not None:
        out["header_ok"] = (struct.unpack(">4I", make_header(int(second)))
                            == struct.unpack(">4I", hdr))
    return out


# ---------------------------------------------------------------------------
# the decoder
# ---------------------------------------------------------------------------
class VmInverse:
    """Fitted inverse for ONE (claims, second)."""

    def __init__(self, second, descs_base, n_templates=N_TEMPLATES,
                 verbose=True, cache_key=None):
        self.second = int(second)
        self.descs_base = [list(t) for t in descs_base]
        self.verbose = verbose
        self.insts = None
        self.known_init = {}
        self.stats = {}
        cpath = None
        if cache_key:
            cpath = os.path.join(HERE, "_vminv_ops_%s.json.gz" % cache_key)
            if os.path.exists(cpath):
                dat = json.load(gzip.open(cpath, "rt"))
                self.insts = [tuple(x) for x in dat["insts"]]
                self.known_init = {int(k): v
                                   for k, v in dat["known_init"].items()}
                self.stats = dat["stats"]
                self._log("[vminv] loaded fitted ops (%s) stats=%s"
                          % (os.path.basename(cpath), self.stats))
                return
        self._fit(n_templates)
        if cpath:
            json.dump({"insts": [list(x) for x in self.insts],
                       "known_init": {str(k): v for k, v in
                                      self.known_init.items()},
                       "stats": self.stats},
                      gzip.open(cpath, "wt"))

    def _log(self, msg):
        if self.verbose:
            print(msg, flush=True)

    def _fit(self, n_templates):
        rng = random.Random(0x5EED1)
        t0 = time.time()
        base = [tuple(t) for t in self.descs_base]
        templates = []
        for i in range(n_templates):
            descs = _region_descs(base, rng)
            cap = capture(self.second, descs)
            templates.append(cap)
            self._log("[vminv] template %d/%d: %s %.0fs record=%s.. blob=%s.."
                      % (i + 1, n_templates, cap["status"], cap["sec"],
                         cap["record"][:6].hex(), cap["blob"][:6].hex()))
        insts, stats, unresolved = fit_ops(templates)
        _, insts = trim_schedule(insts)
        self.insts = insts
        self.stats = stats
        self._log("[vminv] pipeline: %d events, stats %s (%.0fs)"
                  % (len(insts), stats, time.time() - t0))
        if unresolved:
            self._log("[vminv] %d UNRESOLVED, first: %s"
                      % (len(unresolved),
                         [(k, hex(o), "%02x" % c, "%02x" % v,
                           [(a, "%02x" % b) for a, b in t])
                          for (k, (idx, o, c, t, v)) in unresolved[:3]]))
        # known-init: tapped positions never written inside the pipeline
        # whose final value is identical across templates (constants)
        written = {o for (o, op, K, taps, extra) in insts if op != "ERR"}
        tapped = {t for (o, op, K, taps, extra) in insts for t in taps}
        ki = {}
        bad = 0
        for tpos in sorted(tapped - written):
            vals = set()
            for t in templates:
                lv = None
                for (kind, pc, o, v) in t["events"]:
                    if o == tpos and kind == "E":
                        lv = v
                vals.add(lv)
            if len(vals) == 1 and None not in vals:
                ki[tpos] = vals.pop()
            else:
                bad += 1
        self.known_init = ki
        self._log("[vminv] known-init positions: %d (%d tapped-but-variant)"
                  % (len(ki), bad))

    # -- decode ------------------------------------------------------------
    def decode(self, blob, do_remint=True):
        """192-B blob -> dict with record/S/head/region + checks."""
        blob = bytes(blob)
        rec, hdr, rep = backward(blob, self.insts, self.known_init)
        chk = record_checks(rec, hdr, self.second)
        reg = region_from_record(rec)
        out = {"record": rec.hex(), "record_raw": rec, "header": hdr.hex(),
               "seed": reg["seed"], "S": reg["seed"], "phase": reg["phase"],
               "region": None if reg["d0"] is None else
               {"d0": reg["d0"], "d2": reg["d2"], "d4": reg["d4"]},
               "checks": chk, "skipped": rep["skipped"], "remint": None}
        if reg["d0"] is not None and do_remint:
            out["remint"] = self._remint(reg)
        return out

    def _remint(self, reg):
        ds = [list(t) for t in self.descs_base]
        d0 = b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in reg["d0"])
        d2 = struct.pack(">I", reg["d2"] & 0xFFFFFFFF)
        d4 = b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in reg["d4"])
        for bi, data in ((0, d0), (2, d2), (4, d4)):
            i = VA_ORDER.index(bi)
            ds[i][2] = data
            ds[i][0] = len(data) // 4
        cap = capture(self.second, [tuple(t) for t in ds])
        return {"blob": cap["blob"].hex(), "status": cap["status"]}


# ---------------------------------------------------------------------------
# corpus + winners drivers
# ---------------------------------------------------------------------------
def corpus_descs(row, region=None):
    """Descriptor list (VA order) for a corpus row; region = (d0,d2,d4) bytes
    or None for zero placeholders."""
    asg = json.load(open(os.path.join(HERE, "all_signings.json"),
                         encoding="utf-8"))
    r = asg[row]
    if region is None:
        d0, d2, d4 = b"\x00" * 144, b"\x00" * 4, b"\x00" * 32
    else:
        d0, d2, d4 = region
    by = {0: (36, 0, d0),
          9: (5, 0, D9),
          8: (4, 0, D8),
          4: (8, 0, d4),
          2: (1, 0, d2),
          7: (1, 0, bytes.fromhex(r["d7"])),
          10: (len(bytes.fromhex(r["d10"])) // 4, 0,
               bytes.fromhex(r["d10"])),
          5: (1, 0, bytes.fromhex(r["d5"]) if r.get("d5") else b"\x00" * 4),
          6: (1, 0, bytes.fromhex(r["d6"]) if r.get("d6") else b"\x00" * 4),
          1: (0, 0, b""),
          3: (0, 0, b"")}
    return [by[i] for i in VA_ORDER]


def corpus_row(row):
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json"),
                         encoding="utf-8"))
    return int(ph3[row]["second"]), bytes.fromhex(ph3[row]["blob"])


def decode_corpus_row(row, n_templates=N_TEMPLATES, verbose=True):
    second, blob = corpus_row(row)
    descs = corpus_descs(row)
    inv = VmInverse(second, descs, n_templates=n_templates, verbose=verbose,
                    cache_key="row%d" % row)
    t0 = time.time()
    res = inv.decode(blob)
    res["row"] = row
    res["second"] = second
    if verbose:
        chk = res["checks"]
        print("[row %d] consts_ok=%s header_ok=%s phase=%s seed=%08x (%.0fs)"
              % (row, chk.get("consts_ok"), chk.get("header_ok"),
                 res["phase"], res["seed"] & 0xFFFFFFFF, time.time() - t0),
              flush=True)
        asg = json.load(open(os.path.join(HERE, "all_signings.json"),
                             encoding="utf-8"))
        r = asg[row]
        seedcap = int.from_bytes(bytes.fromhex(r["d2"]), "little")
        d2cap = int.from_bytes(bytes.fromhex(r["d2"]), "big")
        d0wcap = struct.unpack(">36I", bytes.fromhex(r["d0"]))
        d4wcap = struct.unpack(">8I", bytes.fromhex(r["d4"]))
        rec = res["record_raw"]
        ok_s = rec[20:24] == struct.pack("<I", seedcap)
        ok_head = rec[3:19] == bytes.fromhex(r["d0"][:16])
        print("[row %d] S %s (want %08x)  head %s  d2 %s"
              % (row, "MATCH" if ok_s else "MISMATCH", seedcap,
                 "MATCH" if ok_head else "MISMATCH",
                 "MATCH" if res["region"] and res["region"]["d2"] == d2cap
                 else "MISMATCH"), flush=True)
        if res["region"]:
            reg = res["region"]
            print("[row %d] region d0=%s d4=%s phase=%s"
                  % (row,
                     "MATCH" if reg["d0"] == list(d0wcap) else "MISMATCH",
                     "MATCH" if reg["d4"] == list(d4wcap) else "MISMATCH",
                     reg["phase"]), flush=True)
        if res["remint"]:
            blobhex = blob.hex()
            rem_ok = res["remint"]["blob"] == blobhex
            nw = sum(1 for k in range(48)
                     if res["remint"]["blob"][4 * k:4 * k + 4] ==
                     blobhex[4 * k:4 * k + 4])
            print("[row %d] remint: %d/48 words %s (status %s)"
                  % (row, nw, "FULL MATCH" if rem_ok else "DIFF",
                     res["remint"]["status"]), flush=True)
            res["remint_ok"] = rem_ok
            res["remint_words"] = nw
    return res


def winners_input():
    """The 6 genuine winning blobs + claims + seconds (decoder2_winners)."""
    win = json.load(open(os.path.join(HERE, "decoder2_winners.json"),
                         encoding="utf-8"))
    out = []
    for w in win:
        claims = dict(w["claims"])
        claims.pop("algorithm", None)          # log-parse artifact
        kind = claims.get("activity_kind") or "session"
        out.append({"i": w["i"], "kind": kind, "second": w["second"],
                    "blob": bytes.fromhex(w["blob"]), "claims": claims})
    return out


def winner_descs(claims, kind, region=None):
    import mint_pipeline as M
    if region is None:
        d0, d2, d4 = b"\x00" * 144, b"\x00" * 4, b"\x00" * 32
    else:
        d0, d2, d4 = region
    descs, _ = M.build_descriptors(claims, kind, d0, d2, d4)
    return descs


def decode_winners(n_templates=N_TEMPLATES, verbose=True):
    out = []
    for w in winners_input():
        second = w["second"]
        if second is None:
            print("[winner %d] no second — skipped" % w["i"], flush=True)
            continue
        descs = winner_descs(w["claims"], w["kind"])
        inv = VmInverse(second, descs, n_templates=n_templates,
                        verbose=verbose, cache_key="win%d" % w["i"])
        t0 = time.time()
        res = inv.decode(w["blob"])
        res["i"] = w["i"]
        res["kind"] = w["kind"]
        res["second"] = second
        chk = res["checks"]
        print("[winner %d %s] second=%d consts_ok=%s header_ok=%s phase=%s "
              "seed=%08x (%.0fs)"
              % (w["i"], w["kind"], second, chk.get("consts_ok"),
                 chk.get("header_ok"), res["phase"],
                 (res["seed"] or 0) & 0xFFFFFFFF, time.time() - t0),
              flush=True)
        if res["remint"]:
            blobhex = w["blob"].hex()
            rem_ok = res["remint"]["blob"] == blobhex
            nw = sum(1 for k in range(48)
                     if res["remint"]["blob"][4 * k:4 * k + 4] ==
                     blobhex[4 * k:4 * k + 4])
            print("[winner %d] remint: %d/48 words %s"
                  % (w["i"], nw, "FULL MATCH" if rem_ok else "DIFF"),
                  flush=True)
            res["remint_ok"] = rem_ok
            res["remint_words"] = nw
        out.append(res)
    return out


# ---------------------------------------------------------------------------
def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "row7"
    if mode == "row7":
        decode_corpus_row(7)
    elif mode == "corpus":
        rows = (0, 1, 4, 5, 6, 7)
        if len(sys.argv) > 2:
            rows = tuple(int(x) for x in sys.argv[2].split(","))
        nok = 0
        for r in rows:
            res = decode_corpus_row(r)
            ok = (res["checks"].get("consts_ok")
                  and res["checks"].get("header_ok")
                  and res.get("remint_ok"))
            nok += bool(ok)
        print("=== vm_inverse CORPUS: %d/%d rows fully decoded+reminted ==="
              % (nok, len(rows)))
    elif mode == "winners":
        decode_winners()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
