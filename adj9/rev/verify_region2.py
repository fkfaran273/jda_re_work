#!/usr/bin/env python3
"""verify_region2.py - RAW-capture verification of the adj9 region seed model.

Reads ONLY raw device captures (device/adj9_wh4.log, device/adj9_wh2.log) and
the rev/*.json descriptor extracts; never trusts notes/*.md.

Tasks (per request):
  1. Recover the 32-bit seed from each real nsign capture's recorded d2
     (invert the little-endian store) and list ts / nano_out.
  2. For each seed, with V = tv_sec ^ tv_usec over the plausible tv_usec range
     of the signing second, report the RANGE of implied pids and whether it
     contains plausible Linux/Android pids.
  3. Same analysis for the production choice (V = make_V(clock), pid = 26530).
  4. Do transmitted millisecond timestamps (created_at / sent_at) constrain V
     enough to collapse the implied pid set?
  5. Sanity-check F.py: F._d4_words(seed) / F._d0_words(...) vs the recorded
     d4 / d0 for the recovered seeds (event-captured descriptors) and against
     the d4 region inside the raw nsign blobs.

Run:  python rev/verify_region2.py
"""
from __future__ import annotations

import json
import os
import re
import struct
import sys
from collections import Counter, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEV = os.path.join(ROOT, "device")
sys.path.insert(0, HERE)

import F  # noqa: E402  (rev/F.py)

MASK32 = 0xFFFFFFFF
MASK16 = 0xFFFF
DEFAULT_PID = 26530           # mint_pipeline.py:76
ANDROID_PID_MAX = 32767       # typical Linux pid_max on Android
TV_USEC_MIN, TV_USEC_MAX = 0, 999_999

# nsign record: BEGIN line, text len, optional nano_out, 192-byte hex blob.
NSIGN_RE = re.compile(
    r"###ADJ9_BEGIN type=nsign utf8len=\d+ ts=(\d+)\n"
    r"text: len=(\d+)\n(?:nano_out=(\d+)\n)?hex=([0-9a-f]+)"
)
SIGN_INPUT_RE = re.compile(
    r"###ADJ9_BEGIN type=sign_input utf8len=\d+ ts=(\d+)\ntext: map_size=\d+\nmap_toString=(\{[^\n]*)"
)
# ISO like 2026-09-12T21:07:55.112Z+0200
ISO_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z([+-]\d{2})(\d{2})"
)


def iso_to_epoch_ms(s: str) -> int | None:
    m = ISO_RE.search(s)
    if not m:
        return None
    y, mo, d, h, mi, sec, msec, tzh, tzm = m.groups()
    sign = -1 if tzh == "-" else 1
    off_min = sign * (int(tzh) * 60 + int(tzm))
    # days since epoch (civil -> days), Howard Hinnant algorithm
    yy, mm, dd = int(y), int(mo), int(d)
    yy -= mm <= 2
    era = (yy if yy >= 0 else yy - 399) // 400
    yoe = yy - era * 400
    doy = (153 * (mm + (-3 if mm > 2 else 9)) + 2) // 5 + dd - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    total = days * 86400 + int(h) * 3600 + int(mi) * 60 + int(sec) - off_min * 60
    return total * 1000 + int(msec)


# --- header_gen.Random3 (device header law) to recover the blob's true second
from header_gen import make_header  # noqa: E402  (project's verified impl)


def recover_second_from_header(blob: bytes, ts_sec: int, span: int = 3):
    for s in range(ts_sec - span, ts_sec + span + 1):
        if make_header(s) == blob[:16]:
            return s
    return None


def d2_to_seed(d2: int) -> int:
    return int.from_bytes((d2 & MASK32).to_bytes(4, "big"), "little")


def seed_to_d2(seed: int) -> int:
    return int.from_bytes((seed & MASK32).to_bytes(4, "little"), "big")


def f_region_from_seed(seed: int):
    d4 = F._d4_words(seed)
    d0 = F._d0_words(d4)
    return d0, seed_to_d2(seed), d4


def words_hex(words):
    return "".join("%08x" % w for w in words)


def load_nsign_records(log_path: str):
    raw = open(log_path, encoding="utf-8", errors="replace").read()
    recs = []
    for ts, tlen, nano, hx in NSIGN_RE.findall(raw):
        blob = bytes.fromhex(hx)
        recs.append(
            {
                "ts": int(ts),
                "text_len": int(tlen),
                "nano_out": int(nano) if nano else None,
                "blob": blob,
                "ts_sec": int(ts) // 1000,
                "ts_ms": int(ts) % 1000,
            }
        )
    return recs


def load_sign_inputs(log_path: str):
    raw = open(log_path, encoding="utf-8", errors="replace").read()
    out = []
    for ts, text in SIGN_INPUT_RE.findall(raw):
        created = re.search(r"created_at=([^,}]+)", text)
        sent = re.search(r"sent_at=([^,}]+)", text)
        out.append(
            {
                "ts": int(ts),
                "created_at": created.group(1) if created else None,
                "sent_at": sent.group(1) if sent else None,
                "created_ms": iso_to_epoch_ms(created.group(1)) if created else None,
                "sent_ms": iso_to_epoch_ms(sent.group(1)) if sent else None,
            }
        )
    return out


def pair_sign_inputs(recs, inputs):
    """Each nsign is followed by its sign_input record; attach nearest later."""
    for r in recs:
        best = None
        for si in inputs:
            if si["ts"] >= r["ts"] and si["ts"] - r["ts"] <= 5000:
                if best is None or si["ts"] < best["ts"]:
                    best = si
        r["sign_input"] = best


# --- pid analysis -----------------------------------------------------------

def implied_pid(seed: int, V: int) -> int:
    return ((seed ^ V) >> 16) & MASK16


def pid_range_for_second(seed: int, sec: int,
                         usec_lo=TV_USEC_MIN, usec_hi=TV_USEC_MAX):
    """Enumerate tv_usec in [lo,hi] for the signing second; return pid set."""
    pids = set()
    for usec in range(usec_lo, usec_hi + 1):
        V = (sec ^ usec) & MASK32
        pids.add(implied_pid(seed, V))
    return pids


def pid_range_for_ms_window(seed: int, sec: int, ms_lo: int, ms_hi: int):
    """tv_usec constrained to the millisecond window [ms_lo,ms_hi] of `sec`."""
    pids = set()
    for usec in range(ms_lo * 1000, ms_hi * 1000 + 1000):
        V = (sec ^ usec) & MASK32
        pids.add(implied_pid(seed, V))
    return pids


def summarize_pids(pids):
    lo, hi = min(pids), max(pids)
    n = len(pids)
    plausible = sorted(p for p in pids if 1 <= p <= ANDROID_PID_MAX)
    return {
        "n": n,
        "min": lo,
        "max": hi,
        "span": hi - lo,
        "n_plausible": len(plausible),
        "plausible_min": plausible[0] if plausible else None,
        "plausible_max": plausible[-1] if plausible else None,
        "any_plausible": bool(plausible),
    }


def main():
    print("=" * 78)
    print("adj9 region verification - RAW captures only")
    print("F.py: seed = (V ^ (pid<<16)) & 0xFFFFFFFF, d2 = LE-store(seed) read BE")
    print("mint_pipeline.py DEFAULT_PID = %d ; Android pid_max = %d"
          % (DEFAULT_PID, ANDROID_PID_MAX))
    print("=" * 78)

    logs = OrderedDict()
    logs["wh4"] = os.path.join(DEV, "adj9_wh4.log")
    logs["wh2"] = os.path.join(DEV, "adj9_wh2.log")

    all_recs = {}
    for name, path in logs.items():
        recs = load_nsign_records(path)
        inputs = load_sign_inputs(path)
        pair_sign_inputs(recs, inputs)
        all_recs[name] = recs
        print("\n[%s] %s" % (name, os.path.relpath(path, ROOT)))
        print("  real nsign captures (192-B hex): %d" % len(recs))
        print("  sign_input records: %d" % len(inputs))
        nano_ct = sum(1 for r in recs if r["nano_out"] is not None)
        print("  captures carrying nano_out: %d / %d" % (nano_ct, len(recs)))

    # ---------------------------------------------------------------- TASK 1
    print("\n" + "=" * 78)
    print("TASK 1 - recovered seeds (invert d2 LE-store) from every nsign capture")
    print("=" * 78)
    print("%-5s %14s %16s %10s %8s %8s %10s" %
          ("log", "ts", "nano_out", "d2(BE)", "seed", "hdr_sec", "pid_hi"))
    task1 = []
    for name, recs in all_recs.items():
        for r in recs:
            b = r["blob"]
            d2 = int.from_bytes(b[144:148], "big")
            seed = d2_to_seed(d2)
            hdr_sec = recover_second_from_header(b, r["ts_sec"])
            pid_hi = (seed >> 16) ^ ((hdr_sec or r["ts_sec"]) >> 16)
            task1.append((name, r, d2, seed, hdr_sec, pid_hi))
            print("%-5s %14d %16s %10s %8s %8s %10d" % (
                name, r["ts"],
                r["nano_out"] if r["nano_out"] is not None else "-",
                "%08x" % d2, "%08x" % seed,
                hdr_sec if hdr_sec is not None else "?", pid_hi))
    print("total captures: %d" % len(task1))

    # blob d2 sanity: does F reproduce the blob's own d4 region?
    print("\n  [sanity] F._d4_words(seed-from-blob-d2) vs blob[148:180]:")
    for name, recs in all_recs.items():
        ok = 0
        for r in recs:
            b = r["blob"]
            seed = d2_to_seed(int.from_bytes(b[144:148], "big"))
            d4b = bytes.fromhex(words_hex(F._d4_words(seed)))
            ok += d4b == b[148:180]
        print("    %s: %d / %d blobs match" % (name, ok, len(recs)))

    # ---------------------------------------------------------------- TASK 2
    print("\n" + "=" * 78)
    print("TASK 2 - implied pid range per capture, V = tv_sec ^ tv_usec")
    print("  (signing second = log ts // 1000; usec swept 0..999999)")
    print("=" * 78)
    print("%-5s %14s %10s %10s %6s %6s %6s %8s %10s" %
          ("log", "ts", "ts_sec", "hdr_sec", "#pid", "pmin", "pmax", "n_plaus", "verdict"))
    task2 = []
    for name, r, d2, seed, hdr_sec, pid_hi in task1:
        sec = r["ts_sec"]
        pids = pid_range_for_second(seed, sec)
        s = summarize_pids(pids)
        # pid = ((seed ^ V) >> 16) & 0xFFFF, V = sec ^ usec, usec < 2^20.
        # (sec^usec)>>16 = (sec>>16) ^ (usec>>16) and usec>>16 in 0..15, so
        # pid takes exactly 16 adjacent values  h^0..h^15  with
        # h = (seed>>16) ^ (sec>>16); the 16 values span [h&0xFFF0, +15].
        h = (seed >> 16) ^ (sec >> 16)
        reachable = (h & 0xFFF0) + 15 <= ANDROID_PID_MAX
        verdict = "all 16 pids <=32767" if reachable else "FORCED pid >32767"
        task2.append((name, r, seed, sec, pids, s, h, reachable))
        print("%-5s %14d %10d %10s %6d %6d %6d %8d %10s" % (
            name, r["ts"], sec, hdr_sec if hdr_sec is not None else "?",
            s["n"], s["min"], s["max"],
            s["n_plausible"], verdict))
    n_reach = sum(1 for t in task2 if t[7])
    print("captures where a plausible pid (<=32767) is reachable: %d / %d"
          % (n_reach, len(task2)))

    # ---------------------------------------------------------------- TASK 3
    print("\n" + "=" * 78)
    print("TASK 3 - production choice: V = make_V(current clock), pid = %d"
          % DEFAULT_PID)
    print("=" * 78)
    import time as _time
    now_ns = _time.time_ns()
    now_sec = now_ns // 1_000_000_000
    usec = (now_ns % 1_000_000_000) // 1000
    V_prod = (now_sec ^ (usec & 0xFFFFF)) & MASK32
    seed_prod = (V_prod ^ ((DEFAULT_PID & MASK16) << 16)) & MASK32
    d2_prod = seed_to_d2(seed_prod)
    print("  now_sec=%d usec=%d  V=%d (0x%08x)" % (now_sec, usec, V_prod, V_prod))
    print("  seed=(V ^ (%d<<16)) = 0x%08x   d2=0x%08x"
          % (DEFAULT_PID, seed_prod, d2_prod))
    # self-consistency: server inverts seed with the exact V it is told
    inferred = implied_pid(seed_prod, V_prod)
    print("  server infers pid from (seed ^ V)/2^16 = %d  (== %d -> self-consistent: %s)"
          % (inferred, DEFAULT_PID, inferred == DEFAULT_PID))
    print("  DEFAULT_PID %d inside Android range 1..%d: %s"
          % (DEFAULT_PID, ANDROID_PID_MAX, 1 <= DEFAULT_PID <= ANDROID_PID_MAX))
    # and what the V=sec^usec model implies about a random production seed
    h_prod = (seed_prod >> 16) ^ (now_sec >> 16)
    print("  under V=sec^usec model, (seed>>16)^(sec>>16) = 0x%04x -> pid_hi forced=%d (>15? %s)"
          % (h_prod, h_prod, h_prod > 15))

    # ---------------------------------------------------------------- Task 3b
    print("\n" + "=" * 78)
    print("TASK 3b - server-side validation model (uses the REAL descriptor d2)")
    print("  The descriptor d2 is NOT plaintext in the 192-B blob (see Task 5c);")
    print("  it is an INPUT to the FinEx VM.  The server, to validate, must")
    print("  enumerate (usec,pid) consistent with the transmitted ms window and")
    print("  recompute F(seed)->descriptors->FinEx, comparing to the blob.")
    print("  pid = (seed>>16) ^ (sec>>16) ^ (usec>>16), usec>>16 in 0..15.")
    print("  => per millisecond window the server has <=2 candidate pids and")
    print("     ~1000 candidate usec values; the region IS recomputable in")
    print("     principle, so a wrong/fixed pid or a V outside the window is a")
    print("     detectable tell.")
    # demonstrate the <=2 candidate collapse on a genuine descriptor d2
    d2s = [r["d2"] for r in json.load(open(os.path.join(HERE, "all_signings.json"),
                                          encoding="utf-8"))]
    d2s = list(OrderedDict.fromkeys(d2s))
    d2_collapse = []
    for d2h in d2s:
        seed = d2_to_seed(int(d2h, 16))
        # pretend a server that knows only the second, sweeps one ms window
        for sec_guess in (0,):  # we have no trusted sec; report the structure
            pass
        # Structural fact independent of sec: within one second, 16 adjacent
        # pids; within one millisecond, <=2.  Show on a real d2 with its own
        # high-16 vs a representative second.
        sec = 1789240076
        usec_hi_vals = sorted({(usec >> 16) for usec in range(112 * 1000, 112 * 1000 + 1000)})
        pids = sorted({((seed >> 16) ^ (sec >> 16) ^ k) & MASK16 for k in usec_hi_vals})
        d2_collapse.append((d2h, seed, sec, usec_hi_vals, pids))
    for d2h, seed, sec, uv, pids in d2_collapse[:3]:
        print("   d2=%s seed=%08x sec=%d usec>>16 vals=%s -> pids=%s (n=%d)"
              % (d2h, seed, sec, uv, pids, len(pids)))
    coll = [len(p) for _, _, _, _, p in d2_collapse]
    print("   candidate-pid count per 1-ms window across real d2 set: min=%d max=%d mean=%.2f"
          % (min(coll), max(coll), sum(coll) / len(coll)))

    # ---------------------------------------------------------------- TASK 4
    print("\n" + "=" * 78)
    print("TASK 4 - do created_at / sent_at (ms precision) constrain V?")
    print("  (usec restricted to the signed millisecond window)")
    print("=" * 78)
    print("%-5s %14s %8s %8s %8s %10s %10s %10s" %
          ("log", "ts", "sec", "cre_ms", "sent_ms", "#pid_full", "#pid_ms", "n_plaus_ms"))
    ms_rows = 0
    ms_plaus = 0
    full_n = []
    ms_n = []
    for name, r, d2, seed, hdr_sec, _ in task1:
        si = r.get("sign_input")
        if not si or si["created_ms"] is None or si["sent_ms"] is None:
            continue
        # "consistent with the transmitted second" -> use created_at's second
        # (the claim-map wall-clock second actually transmitted to the server).
        cre_sec = si["created_ms"] // 1000
        cre_ms = si["created_ms"] % 1000
        sent_sec = si["sent_ms"] // 1000
        sent_ms = si["sent_ms"] % 1000
        # the fill instant lies between created_at and sent_at (same second in
        # every observed capture); keep only same-second windows, else fall
        # back to the created_at millisecond alone.
        if sent_sec == cre_sec and sent_ms >= cre_ms:
            lo, hi = cre_ms, sent_ms
        else:
            lo, hi = cre_ms, cre_ms
        # full-second pid set on the SAME transmitted second (unconstrained V)
        pids_full = pid_range_for_second(seed, cre_sec)
        # millisecond-constrained pid set
        pids_ms = pid_range_for_ms_window(seed, cre_sec, lo, hi)
        s_ms = summarize_pids(pids_ms)
        full_n.append(len(pids_full))
        ms_n.append(len(pids_ms))
        ms_rows += 1
        ms_plaus += s_ms["n_plausible"]
        print("%-5s %14d %8d %8d %8d %10d %10d %10d" % (
            name, r["ts"], cre_sec, cre_ms, sent_ms,
            len(pids_full), len(pids_ms), s_ms["n_plausible"]))
    print("captures with sign_input ms timestamps: %d" % ms_rows)
    if ms_rows:
        print("pid-set size: full-second mean=%.0f  ms-window mean=%.0f" % (
            sum(full_n) / len(full_n), sum(ms_n) / len(ms_n)))
        print("total plausible pids across ms-windows: %d (mean %.2f per capture)"
              % (ms_plaus, ms_plaus / ms_rows))
        print("VERDICT task4: %s" % (
            "ms timestamps COLLAPSE the pid set (small set -> server COULD validate)"
            if ms_plaus / ms_rows < 50 else
            "ms timestamps do NOT collapse the pid set (stays large -> server CANNOT validate)"))

    # ---------------------------------------------------------------- TASK 5
    print("\n" + "=" * 78)
    print("TASK 5 - F.py sanity: F(seed) vs recorded d0/d4/d2")
    print("=" * 78)
    # 5a: event-captured descriptors (all_signings.json / pair_h*.json)
    als_path = os.path.join(HERE, "all_signings.json")
    ok4 = ok0 = tot = 0
    mism = []
    for r in json.load(open(als_path, encoding="utf-8")):
        seed = d2_to_seed(int(r["d2"], 16))
        d4 = words_hex(F._d4_words(seed))
        d0 = words_hex(F._d0_words(F._d4_words(seed)))
        m4 = d4 == r["d4"]
        m0 = d0 == r["d0"]
        ok4 += m4
        ok0 += m0
        tot += 1
        if not (m4 and m0):
            mism.append((r["src"], r["d2"], m4, m0))
    print("all_signings.json: d4 match %d/%d, d0 match %d/%d" % (ok4, tot, ok0, tot))
    for src, d2, m4, m0 in mism:
        print("   mismatch: src=%s d2=%s d4=%s d0=%s" % (src, d2, m4, m0))

    # 5b: event-captured pair_h*.json (real device seconds, real d0/d2/d4)
    for pf in ("pair_h.json", "pair_h2.json", "pair_h3.json"):
        p = os.path.join(HERE, pf)
        if not os.path.exists(p):
            continue
        rows = json.load(open(p, encoding="utf-8"))
        a4 = a0 = n = 0
        for r in rows:
            seed = d2_to_seed(int(r["d2"], 16))
            d4 = words_hex(F._d4_words(seed))
            d0 = words_hex(F._d0_words(F._d4_words(seed)))
            a4 += d4 == r["d4"]
            a0 += d0 == r["d0"]
            n += 1
        print("%s: F(seed) reproduces d4 %d/%d, d0 %d/%d" % (pf, a4, n, a0, n))

    # 5c: are the event-captured d2 values present inside the raw nsign blobs?
    #     (Do the descriptors live in the wire blob at all?)
    all_seed_hex = set()
    for pf in ("pair_h.json", "pair_h2.json", "pair_h3.json", "all_signings.json"):
        p = os.path.join(HERE, pf)
        if os.path.exists(p):
            for r in json.load(open(p, encoding="utf-8")):
                all_seed_hex.add(bytes.fromhex(r["d2"]))
    present = 0
    for name, recs in all_recs.items():
        for r in recs:
            b = r["blob"]
            if b[144:148] in all_seed_hex:
                present += 1
    print("event-captured d2 bytes found at blob[144:148]: %d / %d captures"
          % (present, len(task1)))

    # 5d: does F reproduce the RAW blob's own d4 region from ITS OWN d2?
    #     (this is the decisive in-blob check)
    print("F(seed-from-blob-d2) vs blob[148:180] d4 region:")
    for name, recs in all_recs.items():
        ok = 0
        for r in recs:
            b = r["blob"]
            seed = d2_to_seed(int.from_bytes(b[144:148], "big"))
            ok += bytes.fromhex(words_hex(F._d4_words(seed))) == b[148:180]
        print("   %s: %d / %d" % (name, ok, len(recs)))

    # ---------------------------------------------------------------- verdict
    print("\n" + "=" * 78)
    print("VERDICT SUMMARY")
    print("=" * 78)
    # (a) region model correctness
    als_ok = (ok4 == tot)
    blob_ok = all(
        bytes.fromhex(words_hex(F._d4_words(d2_to_seed(int.from_bytes(r["blob"][144:148], "big"))))) == r["blob"][148:180]
        for r in all_recs["wh4"]
    )
    print("(a) region model:")
    print("    F(seed)->d4/d0 reproduces the EVENT-captured descriptors: %s (%d/%d d4)"
          % (als_ok, ok4, tot))
    print("    F(seed-from-LOG-d2) reproduces the LOG blob's own d4: %s" % blob_ok)
    if als_ok and not blob_ok:
        print("    => The algebra is self-consistent, but the d2 at blob[144:148]")
        print("       is NOT the descriptor d2 the F model describes.  The wire")
        print("       blob is a FinEx-mixed stream; the region descriptors live in")
        print("       the nsign event capture, not as plain bytes at those offsets.")
    # (b) pid/V plausibility
    print("(b) pid/V plausibility:")
    print("    DEFAULT_PID=%d is inside Android range 1..%d: %s"
          % (DEFAULT_PID, ANDROID_PID_MAX, 1 <= DEFAULT_PID <= ANDROID_PID_MAX))
    print("    The seed is NOT transmitted, only d2 (=LE-store(seed)); with V")
    print("    unknown, the server cannot invert d2 to a unique seed/without V.")
    print("    Our seed = (now_sec^now_usec) ^ (26530<<16) keeps pid_hi=0 always,")
    print("    so it stays inside the plausible pid range by construction.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
