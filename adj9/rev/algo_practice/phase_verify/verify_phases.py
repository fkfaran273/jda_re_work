"""verify_phases.py — is the pure d0/selector path EXACTLY the native VM's?

Two independent halves:

  PART A (pure, no VM, ~1 s)   audit _d0_words / _selector_halfword against
      the 6 captured VM probe d0 streams (all 36 words each) and against the
      12 genuine pool selector literals.

  PART B (VM, ~15-25 s/run)    drive the REAL FinEx VM (adj9sign/signer_simple.py
      finex_mint) with a descriptor plane whose #0 is built by
      pure_sign.region(S, 0, 0, head=phase), and diff its 192-byte blob
      against pure_sign.sign_pure(..., head=phase) byte for byte.  Covers
      pool phases AND arbitrary phases (mask domain edges 3 and 255).

Usage:
    python verify_phases.py partA                # pure only
    python verify_phases.py partB --only C,E      # selected cases
    python verify_phases.py all
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ALGO = os.path.dirname(HERE)                      # .../algo_practice
REV = os.path.dirname(ALGO)                       # .../rev
SIGNER_SIMPLE = r"C:\Users\Apps\Downloads\com.penti.app\adj9sign\signer_simple.py"

sys.path.insert(0, os.path.join(ALGO, "pure_signer"))
import pure_sign as P                               # noqa: E402

D9 = P.D9_PENTI
D9_CREDIT = P.D9_CREDITSEA
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]

# ------------------------------------------------------------------ cases
# (id, second, S, kind, head phase, d0 tail scramble)
CASES = [
    ("A", 1790625704, 0xA6DA5D2B, "session", (43,)),             # pool lit
    ("B", 1790625704, 0xA6DA5D2B, "session", (43, 72)),           # pool pair
    ("C", 1790625704, 0xA6DA5D2B, "session", (5,)),               # arbitrary
    ("D", 1790625800, 0x11223344, "session", (90,)),              # arbitrary
    ("E", 1790625900, 0x55667788, "session", (126,)),             # mask 255
    ("F", 1790626000, 0xDEADBEEF, "session", (0,)),               # mask 3
    ("G", 1790626100, 0x0BADC0DE, "session", (17,)),              # arbitrary
    ("H", 1790626200, 0xA6DA5D2B, "session", (43, 7, 34, 46)),    # re-sign
    ("I", 1790625704, 0xA6DA5D2B, "session", (43, 72), "tail"),   # structural
    ("J", 1790626300, 0x12345678, "click", (61,)),                # other kind
    ("K", 1790626400, 0x0F1E2D3C, "session", (126, 5, 0, 90, 17, 43)),
    ("L", 1790626500, 0xCAFEBABE, "session", (200,)),             # mask >8 bits
]

BASE_MAP = dict(P._PROBE_BASE)
# a plausible click-kind map: click law reads a few extra keys
CLICK_MAP = dict(BASE_MAP)
CLICK_MAP.update({
    "click_time": "2026-10-01T09:15:00.000Z+0530",
    "click_time_server": "2026-10-01T09:15:04.512Z+0530",
    "google_play_instant": "0",
    "source": "organic",
    "subsession_count": "1",
    "activity_kind": "click",
})


def claims_for(case):
    return CLICK_MAP if case[3] == "click" else BASE_MAP


def build_plane(case):
    """The descriptor plane the VM will be fed (VA_ORDER order)."""
    _id, second, S, kind, head = case[:5]
    scramble = case[5] if len(case) > 5 else None
    d0w, d2, d4w = P.region(S, 0, 0, head=head)
    d0 = bytearray(b"".join(w.to_bytes(4, "big") for w in d0w))
    d4 = b"".join(w.to_bytes(4, "big") for w in d4w)
    if scramble == "tail":
        # zero every d0 byte past the first 16 (the record only carries
        # head16 = d0[0:16]); a blob change would prove the VM reads more.
        d0[16:] = b"\x00" * (len(d0) - 16)
    raw = P.build_claims(claims_for(case), kind)
    padded = raw + b"\x00" * (-len(raw) % 4)
    by = {
        0: (36, 0, bytes(d0)),
        9: (5, 0, bytes.fromhex(D9)),
        8: (4, 0, bytes.fromhex("bffffffffffffd1f0007000000000000")),
        4: (8, 0, d4),
        2: (1, 0, struct.pack(">I", d2)),
        7: (1, 0, struct.pack(">I", len(raw))),
        10: (len(padded) // 4, 0, padded),
        5: (1, 0, b"\x00\x00\x00\x00"),
        6: (1, 0, b"\x00\x00\x00\x00"),
        1: (0, 0, b""),
        3: (0, 0, b""),
    }
    descs = [by[i] for i in VA_ORDER]
    return descs, d0w, d2, d4w, head, kind, S, second, raw


# =========================================================== PART A (pure)
POOL_LITERALS = [0x30, 0x2B, 0x34, 0x37, 0x38, 0x3B, 0x3C, 0x35, 0x36,
                 0x2D, 0x48, 0x05]


def part_a():
    out = {"probes": [], "masks": [], "pool": []}
    print("=" * 78)
    print("PART A - _d0_words / _selector_halfword audit (pure, no VM)")
    print("=" * 78)

    # A1: all 36 words of every captured probe d0
    print("\n[A1] full 36-word d0 vs the 6 captured VM probe streams")
    for f in sorted(glob.glob(os.path.join(ALGO, "probes", "run_r*.json"))):
        d = json.load(open(f, encoding="utf-8"))
        seed = d["seed"]
        cap = [int(x, 16) for x in d["d0"]]
        row = {"tag": d["tag"], "seed": "%08x" % seed, "ncap": len(cap)}
        for lbl, ph in (("43,72", (43, 72)), ("43", (43,))):
            d0w, d2, d4w = P.region(seed, 0, 0, head=ph)
            diff = [i for i, (a, b) in enumerate(zip(d0w, cap)) if a != b]
            row[lbl] = {
                "d0": not diff, "d2": d2 == int(d["d2"], 16),
                "d4": ["%08x" % w for w in d4w] == list(d["d4"]),
                "diff_words": diff,
            }
        out["probes"].append(row)
        r = row["43,72"]
        print("    %-8s seed=%s ncap=%d  ph(43,72): d0=%s d2=%s d4=%s | "
              "ph(43): d0=%s diff_words=%s"
              % (d["tag"], row["seed"], len(cap),
                 r["d0"], r["d2"], r["d4"],
                 row["43"]["d0"], row["43"]["diff_words"]))

    # A2: mask domain + injectivity of the selector->halfword map
    print("\n[A2] selector -> mask map (mask=(s<<1)+3) and selector map domain")
    seeds = [r["seed"] for r in out["probes"]]
    S0 = int(seeds[0], 16)
    src = P._d0_source(P._d4_words(S0))
    print("    d0 source halfwords (seed %s): %s" % (seeds[0],
                                                     " ".join("%04x" % v for v in src)))
    inv = {}
    for v in range(256):
        out["masks"].append(v)
    # which selectors s in 0..126 give an 8-bit mask?
    m_of = {s: (s << 1) + 3 for s in range(127)}
    print("    selector range 0..126 -> mask range %d..%d  (all <=255, 8-bit: %s)"
          % (m_of[0], m_of[126], all(m <= 255 for m in m_of.values())))
    print("    mask(s=126)=%d  mask(s=127)=%d  <- funnel cap keeps it 8-bit"
          % (m_of[126], (127 << 1) + 3))
    # map invertibility: for a fixed d4, distinct masks may collide
    coll = {}
    for m in range(256):
        coll.setdefault(P._selector_halfword(m, src), []).append(m)
    nuniq = len(coll)
    print("    selector_halfword over 256 masks: %d distinct halfwords "
          "(bijective for this d4: %s)" % (nuniq, nuniq == 256))
    out["mask_map_bijective"] = (nuniq == 256)
    # pool literals
    print("\n[A3] the 12 genuine pool selector literals (seed %s)" % seeds[0])
    for s in POOL_LITERALS:
        m = (s << 1) + 3
        h = P._selector_halfword(m, src)
        out["pool"].append({"sel": s, "mask": m, "halfword": h,
                            "bits": bin(m)})
        print("    sel 0x%02x -> mask %3d (%s) -> halfword 0x%04x"
              % (s, m, bin(m), h))

    # A4: cross-seed consistency of the pool expansion (pure)
    print("\n[A4] pool expansion FORM: source-subset shape per literal")
    shapes = {}
    for s in POOL_LITERALS:
        m = (s << 1) + 3
        shapes.setdefault(s, tuple(i for i in range(8) if (m >> i) & 1))
    print("    distinct source-subset shapes among the 12 literals: %d"
          % len(set(shapes.values())))
    out["pool_shapes"] = len(set(shapes.values()))
    out["pool_bits"] = {("0x%02x" % s): list(shapes[s]) for s in shapes}

    # A5: does any d0 word past the first 4 feed anything in the pure path?
    print("\n[A5] pure record consumes d0 words 0..3 only (head16 = d0[0:16])")
    d0w = P._d0_words(P._d4_words(S0), head=(43, 72))
    print("    head_words(d0w)[:4] -> %s   (d0 words used: 0..3 of 36)"
          % P.head_words(d0w)[:8].hex())
    out["d0_words_used_by_pure"] = 4

    # A6: the pure gate's own gold vectors - do the genuine captures still
    # solve to their pool phases (an independent d0/law regression)?
    print("\n[A6] pure_sign.py's own gate (genuine captures, end-to-end)")
    golds = []
    try:
        for second, blob, val, kind in P._mine_creditsea():
            golds.append(("creditsea", second, blob, val, kind, D9_CREDIT))
        for second, blob, val, kind in P._mine_penti_wins():
            golds.append(("penti", second, blob, val, kind, D9))
    except Exception as e:
        print("    (gold mining unavailable: %r)" % (e,))
    nok = 0
    for tag, second, blob, val, kind, d9 in golds:
        if second is None:
            print("    %-10s second UNRESOLVED  SKIP" % tag)
            continue
        good, phase, dec, got = P._gold_check(second, blob, val, kind, d9)
        nok += good
        golds.append(None) if False else None
        print("    %-10s second=%-11s S=%08x kind=%-10s head=%-12s %s"
              % (tag, second, dec["S"], kind,
                 "(" + " ".join("%02x" % x for x in phase) + ")" if phase
                 else "UNRESOLVED",
                 "BYTE-EXACT" if good else "FAIL"))
    print("    -> %d/%d byte-exact" % (nok, len(golds)))
    out["gold_gate"] = {"ok": nok, "n": len(golds)}
    return out


# =========================================================== PART B (the VM)
def _load_vm():
    """Import the real FinEx VM module by absolute path (not on sys.path)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("signer_simple", SIGNER_SIMPLE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["signer_simple"] = mod
    spec.loader.exec_module(mod)
    return mod


def run_case(case):
    """Drive the real FinEx VM once and diff against the pure signer."""
    SS = _load_vm()

    descs, d0w, d2, d4w, head, kind, S, second, raw = build_plane(case)
    t0 = time.perf_counter()
    blob_vm, info = SS.finex_mint(descs, second, max_steps=40_000_000)
    t_vm = time.perf_counter() - t0

    blob_pure = P.sign_pure(second, S, claims_for(case), D9, kind, head=head)
    t_pure = time.perf_counter() - t0 - t_vm

    same = bytes(blob_vm) == bytes(blob_pure)
    res = {
        "id": case[0], "second": second, "S": "%08x" % S, "kind": kind,
        "head": list(head), "masks": [(s << 1) + 3 for s in head],
        "scramble": case[5] if len(case) > 5 else None,
        "claims_len": len(raw), "d0": b"".join(
            w.to_bytes(4, "big") for w in d0w).hex(),
        "d2": "%08x" % d2, "d4": ["%08x" % w for w in d4w],
        "vm_status": info.get("status"), "vm_steps": info.get("steps"),
        "vm_stream": hex(info.get("stream", 0)),
        "t_vm": round(t_vm, 2), "t_pure": round(t_pure, 4),
        "blob_vm": bytes(blob_vm).hex(), "blob_pure": blob_pure.hex(),
        "identical": same,
    }
    if not same:
        a, b = bytes(blob_vm), bytes(blob_pure)
        res["first_diff"] = next(i for i in range(192) if a[i] != b[i])
        res["diff_bytes"] = [i for i in range(192) if a[i] != b[i]]
        try:
            dvm = P.decode_blob(a)
            res["vm_record_consts_ok"] = P.record_consts_ok(dvm["record"])
            res["vm_head16"] = dvm["head"].hex()
            res["vm_S"] = "%08x" % dvm["S"]
            res["vm_block"] = dvm["block"].hex()
            res["vm_d9"] = dvm["d9"].hex()
            res["vm_record"] = dvm["record"].hex()
        except Exception as e:                      # pragma: no cover
            res["vm_decode_error"] = repr(e)
        dpu = P.decode_blob(b)
        res["pure_head16"] = dpu["head"].hex()
        res["pure_block"] = dpu["block"].hex()
        res["pure_record"] = dpu["record"].hex()
    else:
        d = P.decode_blob(bytes(blob_vm))
        res["vm_head16"] = d["head"].hex()
        res["vm_S"] = "%08x" % d["S"]
        res["vm_record_consts_ok"] = P.record_consts_ok(d["record"])
        res["head16_matches_pure_d0"] = (
            d["head"] == P.head_words(d0w))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("what", nargs="?", default="all",
                    choices=["partA", "partB", "all"])
    ap.add_argument("--only", default="")
    args = ap.parse_args()

    result = {}
    path = os.path.join(HERE, "verify_result.json")
    prev = {}
    if os.path.exists(path):
        try:
            prev = json.load(open(path, encoding="utf-8"))
        except Exception:
            prev = {}

    if args.what in ("partA", "all"):
        result["partA"] = part_a()

    if args.what in ("partB", "all"):
        want = set(args.only.upper().split(",")) if args.only else None
        print("\n" + "=" * 78)
        print("PART B - REAL VM vs PURE, arbitrary d0 selector phases")
        print("=" * 78)
        rows = []
        for case in CASES:
            if want and case[0] not in want:
                continue
            r = run_case(case)
            rows.append(r)
            print("  [%s] second=%d S=%s kind=%-8s head=%-14s masks=%-14s "
                  "claims=%dB  VM(%.1fs,%s)  %s"
                  % (r["id"], r["second"], r["S"], r["kind"],
                     "(" + ",".join("0x%02x" % h for h in r["head"]) + ")",
                     "[" + ",".join(str(m) for m in r["masks"]) + "]",
                     r["claims_len"], r["t_vm"], r["vm_status"],
                     "IDENTICAL" if r["identical"] else
                     "*** MISMATCH at byte %d ***" % r["first_diff"]))
            sys.stdout.flush()
        n = len(rows)
        ok = sum(1 for r in rows if r["identical"])
        print("\n  -> %d/%d VM-vs-PURE byte-identical (this batch)"
              % (ok, n))
        # merge with previously recorded cases, keyed by id
        prev_rows = {r["id"]: r for r in prev.get("partB", [])}
        for r in rows:
            prev_rows[r["id"]] = r
        merged = [prev_rows[c[0]] for c in CASES if c[0] in prev_rows]
        result["partB"] = merged
        result["partB_summary"] = {
            "ok": sum(1 for r in merged if r["identical"]),
            "n": len(merged)}

    prev.update(result)
    json.dump(prev, open(path, "w", encoding="utf-8"), indent=1)
    print("\n[written] %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
