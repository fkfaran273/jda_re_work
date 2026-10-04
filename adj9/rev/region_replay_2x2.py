#!/usr/bin/env python3
"""region_replay_2x2.py — DRY-RUN-READY harness for the region-provenance 2x2.

THE QUESTION
------------
The server checks the whole 192-B adj9 envelope: a bit-flip ladder showed that
flipping ANY body bit or ANY header bit turns a genuine blob into Organic, so
the remaining un-gated material is the 56-B region (descriptors #0/#2/#4).
That region is a pure function of one 32-bit seed.  Every live arm to date has
minted a FRESH region; none has ever replayed a region the device actually
emitted.  So: does the server accept a region it has NOT seen before, for a
given device identity?

    |                          | original device identity | fresh GAID identity |
    |--------------------------|--------------------------|---------------------|
    | captured device region   |            A             |          B          |
    | fresh F.region(seed)     |            C             |          D          |
    | verbatim genuine control |            G0            |   (bit-flip: GF)    |

A is the ONLY cell in the campaign that has never been sent.  If A is
RECOGNIZED, the region is not provenance-checked and the whole gate is the
fill/seed algebra.  If A is Organic while G0 is RECOGNIZED, region provenance
(never-before-seen) is confirmed as a gate.

SCORING (see `--help` and SCORING below)
---------------------------------------
The bit-flip ladder (py_ladder.py / py_ladder2.py) established the oracle:
  HTTP 400 + {"ask_in":7200000}, no "attribution" key  -> RECOGNIZED
  HTTP 200 + {"attribution":{...,"network":"Organic"}}  -> NOT RECOGNIZED
NOTE: 400/ask_in is a 2-hour poll backoff on an ALREADY-ATTRIBUTED record.  It
is evidence of recognition, NOT of a new booking.  The real question is the
bit-flip-RELATIVE signal, so this harness always ships a matched negative
reference (GF: cell D with one body bit flipped) in the SAME window as every
positive.  A cell counts as recognized only if it matches G0's response class
AND diverges from GF's.

SAFETY
------
`--dry` is the DEFAULT and sends nothing.  `--send` additionally requires the
literal confirmation token, and refuses without it.  In dry mode every request
is fully built, signed, self-checked and written to rev/region_replay_ready/
as the exact bytes that WOULD go on the wire.

USAGE
-----
  python region_replay_2x2.py                     # dry (default)
  python region_replay_2x2.py --dry --rounds 2
  python region_replay_2x2.py --send --confirm SEND-REGION-REPLAY-2X2
"""
import base64
import datetime
import json
import multiprocessing as mp
import os
import random
import struct
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)

import adj9_full_chain as FC          # noqa: E402  (byte-exact SAZ transport)
import mint_pipeline as MP            # noqa: E402  (claims -> descriptors -> VM)
import F                               # noqa: E402  (the region transform)
from desc10_law import build_desc10, desc10_keys  # noqa: E402
from header_gen import Random3, make_header       # noqa: E402

CONFIRM_TOKEN = "SEND-REGION-REPLAY-2X2"
OUTDIR = os.path.join(HERE, "region_replay_ready")
ENDPOINT = "/attribution"
HOST = "app.adjust.com"
URL = "https://app.adjust.com" + ENDPOINT

# Transport identity: the genuine control record IS a moto g42 / Android 12
# record, so every cell uses the matching UA and +0530 wire offset.
FC.UA = FC.MOTO_UA
FC.OFF_MINUTES, FC.OFF_LABEL = 330, "+0530"
FC.ADD_IDFA = False
FC.USE_PROXY = False
FC.USE_DEVICE = False
FC.NO_SIGN = False

# The genuine record's own millisecond stamps (created_at .783, sent_at .810).
CA_MS, SA_MS = 783, 810

# The CORPUS-PROVEN d0 head phases.  See verify_head_phase() below: solving the
# 72 selector masks against every captured d0 in all_signings.json yields
#   first  = (0x22, 0x2E)                  -> reproduces 9/10 captured d0
#   resign = (0x2B, 0x07, 0x22, 0x2E)      -> reproduces the 1 re-sign row
# with the stable 8-cycle (0x40|(i&7)) starting at index 2 in both cases.
#
# These are NOT mint_pipeline.DEVICE_SELECTORS and NOT F.HEAD_FIRST/HEAD_RESIGN
# (those reproduce 0/10 captured d0).  See the FINDING block printed at startup.
TRUE_HEAD_FIRST = (0x22, 0x2E)
TRUE_HEAD_RESIGN = (0x2B, 0x07, 0x22, 0x2E)

DEFAULT_PID = MP.DEFAULT_PID          # 26530
DEFAULT_TID = MP.DEFAULT_TID          # 26593
LEGACY_HEADS = {
    "ds": MP.DEVICE_SELECTORS,
    "first-legacy": F.HEAD_FIRST,
    "resign-legacy": F.HEAD_RESIGN,
}
TRUE_HEADS = {"first": TRUE_HEAD_FIRST, "resign": TRUE_HEAD_RESIGN}


# ===========================================================================
# corpus
# ===========================================================================
def load_genuine():
    """fresh_genuine.json: the verbatim-genuine /attribution record (G0)."""
    g = json.load(open(os.path.join(HERE, "fresh_genuine.json"),
                       encoding="utf-8"))
    raw_q = g["query"]
    q = raw_q.split("?", 1)[1]
    params = {k: v[0] for k, v in
              urllib.parse.parse_qs(q, keep_blank_values=True).items()}
    return {"raw_query": raw_q, "params": params,
            "blob": bytes.fromhex(g["blob_hex"])}


def load_captured_region(row=0):
    """A CAPTURED (d0, d2, d4) — real bytes the device actually emitted."""
    asg = json.load(open(os.path.join(HERE, "all_signings.json"),
                         encoding="utf-8"))
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json"),
                         encoding="utf-8"))
    if not (0 <= row < len(asg)):
        raise SystemExit("captured row %d out of range (have %d)"
                         % (row, len(asg)))
    r = asg[row]
    d0 = bytes.fromhex(r["d0"])
    d2 = bytes.fromhex(r["d2"])
    d4 = bytes.fromhex(r["d4"])
    if (len(d0), len(d2), len(d4)) != (144, 4, 32):
        raise SystemExit("corpus row %d region sizes %s != (144,4,32)"
                         % (row, (len(d0), len(d2), len(d4))))
    second = int(ph3[row]["second"]) if row < len(ph3) else None
    # which corpus-proven phase is this region?
    phase = "?"
    for nm, h in TRUE_HEADS.items():
        if _d0_from(d4, _sel72(h, 0)) == d0:
            phase = nm
    return {"d0": d0, "d2": d2, "d4": d4, "row": row,
            "second": second, "src": r.get("src"), "phase": phase,
            "blob": bytes.fromhex(ph3[row]["blob"]) if row < len(ph3) else None}


# ===========================================================================
# head-phase verification (the FINDING)
# ===========================================================================
def _d0_from(d4b, selectors72):
    src = F._d0_source(list(struct.unpack(">8I", d4b)))
    vals = [F._selector_halfword((s << 1) + 3, src) for s in selectors72]
    raw = b"".join(v.to_bytes(2, "little") for v in vals)
    return raw


def _sel72(head, n_prefix):
    if isinstance(head, tuple) and len(head) == 12:
        return tuple(head[j] if j < 12 else (0x40 | (j & 7)) for j in range(72))
    return tuple(head[j] if j < len(head) else (0x40 | (j & 7))
                 for j in range(72))


def verify_head_phase(quiet=False):
    """Solve the d0 selector masks against every captured d0 in the corpus.

    Returns a dict; prints the finding unless quiet.  This is the evidence that
    TRUE_HEAD_FIRST / TRUE_HEAD_RESIGN (and not DEVICE_SELECTORS /
    F.HEAD_FIRST / F.HEAD_RESIGN) are the phases the device actually emitted.
    """
    asg = json.load(open(os.path.join(HERE, "all_signings.json"),
                         encoding="utf-8"))
    n = len(asg)
    heads = dict(LEGACY_HEADS)
    heads.update(TRUE_HEADS)
    out = {"rows": n, "per_head": {}, "n_covered": 0}
    covered = set()
    for name, head in heads.items():
        hits = 0
        for i, r in enumerate(asg):
            if _d0_from(bytes.fromhex(r["d4"]), _sel72(head, 0)) == \
                    bytes.fromhex(r["d0"]):
                hits += 1
                covered.add(i)
        out["per_head"][name] = "%d/%d" % (hits, n)
    out["n_covered"] = len(covered)
    out["covered"] = sorted(covered)
    if not quiet:
        print("=== head-phase verification vs captured d0 (all_signings.json) ===")
        for k, v in out["per_head"].items():
            mark = "   <== corpus-proven" if k in TRUE_HEADS else ""
            print("    %-13s reproduces captured d0 on %-5s rows%s" % (k, v, mark))
        legacy_bad = [k for k in LEGACY_HEADS if out["per_head"][k] != "0/%d" % n]
        if legacy_bad:
            print("    FINDING: %s reproduce ZERO captured d0.  Every region"
                  % "/".join(legacy_bad))
            print("    they mint is wrong in the first 4 halfwords (8 B) of d0,")
            print("    i.e. every prior live arm that used them sent a region")
            print("    the device could never have produced.")
        print("    corpus-proven phases together cover %d/%d rows."
              % (out["n_covered"], n))
    return out


# ===========================================================================
# variant construction
# ===========================================================================
def _fresh_region(second, ca_ms, pid, tid, head):
    """A FRESH F.region(seed) with V self-consistent with the wire stamps."""
    V = MP.make_V_consistent(second, ca_ms)
    d0w, d2w, d4w = F.region(V, pid, tid, head=head)
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    d2 = struct.pack(">I", d2w & 0xFFFFFFFF)
    return {"d0": d0, "d2": d2, "d4": d4, "V": V, "pid": pid, "tid": tid,
            "head": list(head)}


def _params_for(gen_params, gps, auid, second):
    """Genuine param set, identity swapped and stamps refreshed to `second`."""
    p = dict(gen_params)
    p["gps_adid"] = gps
    p["android_uuid"] = auid
    p["created_at"] = FC.fmt(second - 1, CA_MS).decode()
    p["sent_at"] = FC.fmt(second - 1, SA_MS).decode()
    return p


def _mint_worker(job, q):
    """Subprocess mint (FinEx is ~20 s; 5+5 cells run in parallel)."""
    try:
        val = MP.claims_from_wire(job["params"], job["kind"])
        blob, info = MP.mint_blob_ex(
            val, job["second"], kind=job["kind"],
            V=job.get("V"), pid=job.get("pid"), tid=job.get("tid"),
            region=job.get("region"), head=job.get("head"))
        q.put({"name": job["name"], "ok": True, "blob": blob.hex(),
               "claims": val,
               "d0": info["d0"].hex(), "d2": info["d2"].hex(),
               "d4": info["d4"].hex(), "V": info["V"], "pid": info["pid"],
               "tid": info["tid"], "status": info["status"],
               "steps": info["steps"], "nrand": info["nrand"],
               "second": info["second"],
               "desc10_unpadded": info["desc10_unpadded"],
               "desc10_padded": info["desc10_padded"],
               "stream": info["stream"]})
    except Exception as e:                                  # pragma: no cover
        q.put({"name": job["name"], "ok": False,
               "error": "%s: %s" % (type(e).__name__, e)})


def mint_parallel(jobs):
    q = mp.Queue()
    procs = [mp.Process(target=_mint_worker, args=(j, q)) for j in jobs]
    t0 = time.time()
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    out = {}
    for _ in jobs:
        r = q.get()
        if not r.get("ok"):
            raise SystemExit("mint FAILED for %s: %s"
                             % (r.get("name"), r.get("error")))
        out[r["name"]] = r
    print("  minted %d blobs in %.0fs (parallel)" % (len(jobs), time.time() - t0))
    return out


# ===========================================================================
# self-checks
# ===========================================================================
def _dword_diff(a, b):
    wa = struct.unpack(">48I", a)
    wb = struct.unpack(">48I", b)
    return [i for i in range(48) if wa[i] != wb[i]]


def _x_index(d0b, hits):
    """Which d0 word is the X half-word for this phase?

    mint_pipeline.region_laws hardcodes X at word 1, which is only true of the
    FIRST phase.  The re-sign phase prepends two selectors (0x2B, 0x07), which
    shifts every half-word by two, putting X at word 3.  Solved from the data
    rather than assumed.
    """
    W = struct.unpack(">36I", d0b)
    ps = [p for p, _ in hits]
    return [k for k in range(6) if ps and any(W[k] == W[2 + p + 3] for p in ps)]


def _laws(d0b, d4b):
    """region_laws plus the phase-corrected L3."""
    L = MP.region_laws(d0b, d4b)
    xs = _x_index(d0b, L["L1_hits"])
    L["L3_x_index"] = xs
    L["L3"] = bool(xs)
    return L


def _seed_law(d2b, second, pid):
    """ADVISORY: invert the transmitted seed under the repo's reconstruction law.

    Repo law (mint_pipeline / F.py docstrings):
        seed = (tv_sec ^ tv_usec) ^ (pid << 16),   usec in [0, 999999]
    Given the seed (descriptor #2) and the sign second (the header law), the
    residual  x = seed ^ second = usec ^ (pid << 16).

    KEY POINT — this law CANNOT discriminate, and the harness must not pretend
    it does.  `pid` is never transmitted (it is not in the 21-claim attribution
    set, nor in the header), so a solver is free to pick any pid < 2^16.  For
    ANY x a consistent solution exists: choose usec = x & 0xFFFF (< 65536, always
    inside [0, 999999]) and pid = the unique 16-bit value that zeroes bits
    16..31 of x.  Every seed is therefore consistent with some (usec, pid) and
    a region server can never call a seed "impossible" on this law alone.

    What the law DOES give us is the *implied* (usec, pid) for a chosen pid,
    which is what we report: for a FRESH region we choose V = second ^ usec, so
    the numbers must agree; for a CAPTURED region they are simply whatever the
    device had at its own fill instant.
    """
    seed = int.from_bytes(d2b, "little")
    x = seed ^ int(second)
    usec_lo = x & 0xFFFF
    pid_sol = ((x >> 16) & 0xF) | (((x >> 20) << 4) & 0xFFF0)
    return {"seed_le": "0x%08x" % seed,
            "residual_x": "0x%08x" % x,
            "implied_usec_at_pid%d" % pid: x ^ ((pid & 0xFFFF) << 16),
            "implied_usec_min": usec_lo,
            "implied_pid_for_min_usec": pid_sol,
            "always_satisfiable": usec_lo < 1000000,
            "note": ("usec=%d < 1e6 is consistent; pid is NOT transmitted so "
                     "this law constrains nothing the server could check"
                     % usec_lo) if usec_lo < 1000000 else
                    ("even the minimal usec=%d exceeds the tv_usec range"
                     % usec_lo)}


def self_check(name, blob, info, params, kind, expect_region, genuine_blob,
               second, head_used, region_kind, law_ref=None, verbose=True):
    """Every check the task requires, plus the diff against a genuine envelope."""
    d0 = bytes.fromhex(info["d0"])
    d2 = bytes.fromhex(info["d2"])
    d4 = bytes.fromhex(info["d4"])
    checks = []

    def chk(cid, label, cond, detail=""):
        checks.append({"id": cid, "label": label, "pass": bool(cond),
                       "detail": detail})
        return bool(cond)

    chk("blob_192", "blob is 192 B (48 BE dwords)", len(blob) == 192,
        "%d B" % len(blob))
    hdr = make_header(second)
    chk("header_law", "blob[:16] == make_header(second)", blob[:16] == hdr,
        hdr.hex())
    r3 = Random3(second)
    dr = [r3.next() for _ in range(8)]
    units = tuple(dr[2 * i] ^ dr[2 * i + 1] for i in range(4))
    chk("header_pair_xor", "header == 4 pair-XOR Random3(second) units",
        struct.unpack(">4I", blob[:16]) == units,
        " ".join("%08x" % u for u in units))
    chk("vm_exit_clean", "FinEx exit-clean", info["status"] == "exit-clean",
        info["status"])
    chk("nrand_8", "nrand == 8 (srand re-fires per signing)", info["nrand"] == 8,
        str(info["nrand"]))

    # ---- claims law -----------------------------------------------------
    keys = desc10_keys(kind, info["claims"])
    rebuilt = build_desc10(info["claims"], kind)
    padded, unpadded = MP.claims_for_law(info["claims"], kind)
    chk("claims_law_keys", "desc10 law key set complete (%d keys)" % len(keys),
        len(keys) == len(desc10_keys(kind, info["claims"])),
        "%d keys" % len(keys))
    chk("claims_law_bytes", "build_desc10(claims) == padded #10 == VM input",
        rebuilt.encode("latin1") == padded[:len(rebuilt)]
        and len(padded) % 4 == 0,
        "unpadded=%d padded=%d" % (unpadded, len(padded)))
    chk("desc7_unpadded", "#7 carries the UNPADDED #10 length",
        info["desc10_unpadded"] == unpadded == len(rebuilt),
        "%d" % unpadded)
    mismatch = [k for k in keys
                if k not in MP.INTERNAL_CLAIMS and k != "activity_kind"
                and info["claims"][k] != params.get(k)]
    chk("claims_eq_wire", "every claim == the value that goes on the wire",
        not mismatch, "mismatched: %s" % (mismatch or "none"))

    # ---- region ---------------------------------------------------------
    chk("region_bytes_exact",
        "region bytes == the %s region exactly" % region_kind,
        (d0, d2, d4) == (expect_region["d0"], expect_region["d2"],
                         expect_region["d4"]),
        "d0=%s d2=%s d4=%s" % (d0[:8].hex(), d2.hex(), d4[:8].hex()))
    if region_kind == "fresh":
        d0b = _d0_from(d4, _sel72(head_used, 0))
        chk("head_phase", "fresh d0 == F._d0_words(head=%s)" % (list(head_used),),
            d0b == d0, "head=%s" % (list(head_used),))
        d4m = b"".join(struct.pack(">I", w)
                       for w in F._d4_words(
                           int.from_bytes(d2, "little")))
        chk("d4_from_d2seed", "d4 == F._d4_words(seed read from d2)",
            d4m == d4, "seed=%s" % int.from_bytes(d2, "little").to_bytes(4, "little").hex())
    else:
        chk("head_phase", "captured region carries its own head (verbatim)",
            True, "n/a — bytes injected, no F phase applied")
    laws = _laws(d0, d4)
    # Self-calibration: the CAPTURED GENUINE region is the ground truth.  Only
    # the structural laws the device's own region satisfies are required of a
    # fresh region; a law the genuine bytes break is not a law in this phase.
    for cid, key in (("region_L1", "L1_tile_Rrep"),
                     ("region_L2", "L2_d4_6_hi_eq_R"),
                     ("region_L3", "L3")):
        want = law_ref.get(key) if law_ref else True
        chk(cid, "region law %s%s" % (key,
                                      "" if want else " (not required: the "
                                      "genuine region breaks it in this phase)"),
            laws[key] == want or (not want),
            "got=%s genuine_ref=%s X@word%s" % (laws[key], want,
                                               laws.get("L3_x_index")))

    seed = _seed_law(d2, second, info["pid"])
    chk("seed_law_advisory", "seed inverts to some (usec,pid) — ADVISORY",
        seed["always_satisfiable"], seed["note"])

    # ---- header / envelope ---------------------------------------------
    auth = MP.auth_header(blob)
    chk("auth_header", "Authorization == adj9_full_chain._auth_header",
        auth == FC._auth_header(blob), "%d chars" % len(auth))
    b64 = base64.b64encode(blob).decode()
    chk("auth_b64", "auth signature= decodes back to the 192-B blob",
        base64.b64decode(b64) == blob, b64[:32] + "...")
    diff = _dword_diff(blob, genuine_blob)
    chk("envelope_shape", "192-B envelope = 16-B header + 44 body dwords",
        len(blob) == 16 + 44 * 4,
        "%d/48 dwords differ from the (different-second) genuine blob"
        % len(diff))

    ok = all(c["pass"] or c["id"] == "seed_law_advisory" for c in checks)
    if verbose:
        print("\n  --- %s ---" % name)
        for c in checks:
            tag = "PASS" if c["pass"] else "FAIL"
            note = "" if c["id"] != "seed_law_advisory" else "  (advisory)"
            print("    [%s] %-22s %s%s"
                  % (tag, c["id"], c["label"], note))
            if c["detail"]:
                print("           %s" % c["detail"])
        print("    => %s" % ("ALL CHECKS PASS" if ok else "*** FAILURES ***"))
    return {"checks": checks, "ok": ok, "seed_law": seed,
            "diff_vs_genuine_dwords": diff, "region_laws": laws}


# ===========================================================================
# request rendering (the exact bytes that WOULD be sent)
# ===========================================================================
def enc(params):
    """urlencode that matches the GENUINE capture byte-for-byte.

    urllib's default quote_plus turns ' ' into '+', but every genuine capture
    encodes it as %20 (fresh_genuine.json: device_name=moto%20g42).  Use quote
    so the crafted cells are a minimal byte-delta from the genuine envelope —
    which is the whole point of a bit-flip-relative experiment.
    """
    return urllib.parse.urlencode(params, quote_via=urllib.parse.quote)


def render_request(params, blob, raw_query=None):
    """Byte-exact FC.send() GET /attribution, as http.client lays it out."""
    if raw_query is not None:
        path = raw_query                      # verbatim, control only
    else:
        path = ENDPOINT + "?" + enc(params)
    auth = FC._auth_header(blob)
    lines = ["GET %s HTTP/1.1" % path,
             "Client-SDK: android5.7.0",
             "Authorization: " + auth,
             "User-Agent: " + FC.UA,
             "Host: " + HOST,
             "Connection: Keep-Alive",
             "Accept-Encoding: gzip",
             "", ""]
    return "\r\n".join(lines), path, b""


def build_plan(gen, cap, second, gps_fresh, auid_fresh, head, pid, tid,
               cap_row, rounds, order, shuffle_seed, remint):
    """The 2x2 + controls, fully signed, self-checked.  Sends nothing."""
    gps_orig, auid_orig = gen["params"]["gps_adid"], gen["params"]["android_uuid"]
    cap_reg = {"d0": cap["d0"], "d2": cap["d2"], "d4": cap["d4"],
               "row": cap["row"]}
    fresh_reg = _fresh_region(second, CA_MS, pid, tid, head)

    cells = [
        ("A", "orig_id+CAPTURED_region", gps_orig, auid_orig, cap_reg,
         "captured"),
        ("B", "fresh_id+CAPTURED_region", gps_fresh, auid_fresh, cap_reg,
         "captured"),
        ("C", "orig_id+FRESH_region", gps_orig, auid_orig, fresh_reg, "fresh"),
        ("D", "fresh_id+FRESH_region", gps_fresh, auid_fresh, fresh_reg,
         "fresh"),
    ]

    jobs, meta = [], {}
    for nm, desc, gps, auid, reg, rk in cells:
        params = _params_for(gen["params"], gps, auid, second)
        j = {"name": nm, "params": params, "kind": "attribution",
             "second": second}
        if rk == "captured":
            j["region"] = (reg["d0"], reg["d2"], reg["d4"])
            j["V"] = None
        else:
            j["V"] = fresh_reg["V"]
            j["pid"] = pid
            j["tid"] = tid
            j["head"] = head
        jobs.append(j)
        meta[nm] = {"desc": desc, "region_kind": rk, "gps_adid": gps,
                    "android_uuid": auid, "expect_region": reg,
                    "head": list(head) if rk == "fresh" else None}
    if remint:
        for nm in [c[0] for c in cells]:
            j = dict(jobs[[c[0] for c in cells].index(nm)])
            j["name"] = nm + "#re"
            jobs.append(j)

    law_ref = _laws(cap["d0"], cap["d4"])
    print("  law reference (from the CAPTURED GENUINE region): L1=%s L2=%s L3=%s"
          " (X@word%s)" % (law_ref["L1_tile_Rrep"], law_ref["L2_d4_6_hi_eq_R"],
                           law_ref["L3"], law_ref["L3_x_index"]))
    print("  minting %d job(s) for second=%d ..." % (len(jobs), second))
    mints = mint_parallel(jobs)

    variants = {}
    cell_params = {nm: j["params"] for nm, j in zip([c[0] for c in cells], jobs)}
    for nm, desc, gps, auid, reg, rk in cells:
        m = mints[nm]
        blob = bytes.fromhex(m["blob"])
        params_n = cell_params[nm]
        res = self_check(nm, blob, m, params_n, "attribution", reg,
                         gen["blob"], second, head, rk, law_ref=law_ref)
        raw, path, _ = render_request(params_n, blob)
        variants[nm] = {"name": nm, "desc": desc, "region_kind": rk,
                        "params": params_n,
                        "blob": blob, "blob_hex": m["blob"],
                        "auth": FC._auth_header(blob), "raw_request": raw,
                        "path": path, "checks": res,
                        "gps_adid": gps, "android_uuid": auid,
                        "sign_second": second, "head": meta[nm]["head"],
                        "V": m["V"], "pid": m["pid"], "tid": m["tid"],
                        "region": {"d0": m["d0"], "d2": m["d2"], "d4": m["d4"]},
                        "claims": m["claims"],
                        "desc10_unpadded": m["desc10_unpadded"],
                        "desc10_padded": m["desc10_padded"],
                        "vm": {"status": m["status"], "steps": m["steps"],
                               "nrand": m["nrand"], "stream": m["stream"]}}
        if remint:
            variants[nm]["remint_identical"] = (mints[nm + "#re"]["blob"]
                                                == m["blob"])

    # ---- controls --------------------------------------------------------
    g0 = {"name": "G0", "desc": "verbatim genuine (control)",
          "raw_request": render_request(None, gen["blob"],
                                        raw_query=gen["raw_query"])[0],
          "path": gen["raw_query"], "blob_hex": gen["blob"].hex(),
          "auth": FC._auth_header(gen["blob"]), "params": gen["params"],
          "verbatim": True, "checks": None}
    d = variants["D"]
    flip = bytearray(d["blob"])
    flip[-1] ^= 1
    flip = bytes(flip)
    gf = {"name": "GF", "desc": "cell D with 1 body bit flipped (negative ref)",
          "raw_request": render_request(d["params"], flip)[0],
          "path": render_request(d["params"], flip)[1],
          "blob_hex": flip.hex(), "auth": FC._auth_header(flip),
          "params": d["params"], "flip_offset": len(d["blob"]) - 1,
          "checks": {"ok": True,
                     "note": "byte-identical to D except 1 bit at offset %d"
                             % (len(d["blob"]) - 1)}}
    return variants, {"G0": g0, "GF": gf}, meta, fresh_reg


# ===========================================================================
# scoring (bit-flip-relative)
# ===========================================================================
def classify(status, body):
    """RECOGNIZED / NOT_RECOGNIZED / UNKNOWN from the ladder oracle."""
    try:
        j = json.loads(body)
    except Exception:
        return ("RECOGNIZED" if status == 400 and "ask_in" in (body or "")
                else "UNKNOWN", {})
    if "attribution" in j:
        a = j["attribution"]
        return ("NOT_RECOGNIZED" if a.get("network") == "Organic"
                else "SEEN(%s)" % a.get("network"),
                {"tracker_token": a.get("tracker_token"),
                 "network": a.get("network")})
    if status == 400 and "ask_in" in j:
        return "RECOGNIZED", {"ask_in": j.get("ask_in")}
    return "UNKNOWN", {}


def score(results):
    """Bit-flip-relative scoring.  Never scores on the 400/200 gloss alone."""
    g0 = results.get("G0", {})
    gf = results.get("GF", {})
    c0, c00 = classify(g0.get("status"), g0.get("body", ""))
    cf, _ = classify(gf.get("status"), gf.get("body", ""))
    rows = []
    for nm in ("G0", "GF", "A", "B", "C", "D"):
        r = results.get(nm)
        if not r:
            continue
        c, info = classify(r.get("status"), r.get("body", ""))
        if nm in ("G0", "GF"):
            verdict = c
        else:
            if c0 == "RECOGNIZED" and c == c0 and c != cf:
                verdict = "RECOGNIZED (matches G0, diverges from GF)"
            elif c == cf:
                verdict = "NOT_RECOGNIZED (matches the bit-flip control)"
            else:
                verdict = "%s (does not match either control)" % c
        rows.append({"cell": nm, "http": r.get("status"),
                     "class": c, "verdict": verdict, "detail": info,
                     "body": (r.get("body") or "")[:300]})
    return {"control_G0": c0, "control_GF": cf, "rows": rows}


# ===========================================================================
# disk output
# ===========================================================================
def write_out(tag, variants, controls, meta, fresh_reg, second, args, head):
    d = os.path.join(OUTDIR, tag)
    os.makedirs(d, exist_ok=True)
    everything = dict(variants)
    everything.update(controls)
    manifest = {"tag": tag, "second": second, "generated": time.time(),
                "sign_second": second,
                "captured_region": {
                    "row": meta["A"]["expect_region"].get("row"),
                    "d0": meta["A"]["expect_region"]["d0"].hex(),
                    "d2": meta["A"]["expect_region"]["d2"].hex(),
                    "d4": meta["A"]["expect_region"]["d4"].hex()},
                "fresh_region": {k: (v.hex() if isinstance(v, bytes) else v)
                                 for k, v in fresh_reg.items()},
                "head": list(head), "pid": args.pid, "tid": args.tid,
                "gps_orig": meta["A"]["gps_adid"],
                "gps_fresh": meta["B"]["gps_adid"],
                "auid_orig": meta["A"]["android_uuid"],
                "auid_fresh": meta["B"]["android_uuid"],
                "cells": {k: {"desc": v["desc"],
                              "region_kind": v.get("region_kind", "control"),
                              "gps_adid": v.get("gps_adid"),
                              "android_uuid": v.get("android_uuid"),
                              "diff_vs_genuine_dwords":
                                  v["checks"].get("diff_vs_genuine_dwords")
                                  if v.get("checks") else None,
                              "ok": v["checks"]["ok"] if v.get("checks") else None,
                              "path": v["path"]}
                          for k, v in everything.items()},
                "cross_cell_dwords_differ": {
                    "%s_vs_%s" % (a, b): len(
                        _dword_diff(variants[a]["blob"], variants[b]["blob"]))
                    for a, b in (("A", "C"), ("A", "B"), ("C", "D"), ("A", "D"))}}
    json.dump(manifest, open(os.path.join(d, "manifest.json"), "w"), indent=1)
    hv = verify_head_phase(quiet=True)
    manifest["head_verification"] = hv
    json.dump(manifest, open(os.path.join(d, "manifest.json"), "w"), indent=1)
    plan = [
        "REGION-PROVENANCE 2x2 — READY-TO-SEND PLAN (nothing was sent)",
        "=" * 70,
        "sign second : %d" % second,
        "endpoint    : GET https://app.adjust.com/attribution",
        "User-Agent  : %s" % FC.UA,
        "d0 head     : %s   pid=%d tid=%d" % (list(head), args.pid, args.tid),
        "",
        "CELLS (all share the sign second; header is identical across A-D):",
    ]
    for nm in ("A", "B", "C", "D"):
        v = variants[nm]
        plan.append("  %s  %-28s gps_adid=%s  ok=%s"
                    % (nm, v["desc"], v["gps_adid"], v["checks"]["ok"]))
    plan += [
        "  G0  verbatim-genuine control  (recognition positive reference)",
        "  GF  cell D with 1 body bit flipped at offset 191 "
        "(bit-flip negative reference)",
        "",
        "SCORING — bit-flip-relative, never the 400/200 gloss:",
        "  RECOGNIZED       = HTTP 400 + {\"ask_in\":...} and NO \"attribution\" key",
        "  NOT_RECOGNIZED   = HTTP 200 + attribution.network == \"Organic\"",
        "  A/B/C/D count as recognized only if the class matches G0 AND",
        "  diverges from GF in the SAME window.",
        "  400/ask_in is a 2-hour poll backoff on an already-attributed record;",
        "  it is evidence of recognition, NOT of a new booking.",
        "",
        "READING THE 2x2 (G0=RECOGNIZED, GF=NOT_RECOGNIZED assumed):",
        "  A rec, C org  -> region provenance IS a gate (never-seen region refused)",
        "  A org, C org  -> not provenance; the fill/seed algebra is the whole gate",
        "  A rec, C rec  -> region fully synthesizable; the gate is elsewhere",
        "  B vs A        -> does region provenance depend on device identity",
        "  D vs C        -> same question on the fresh-identity side",
        "",
        "FILES:",
    ]
    for nm in ("G0", "GF", "A", "B", "C", "D"):
        plan.append("  %s.http.txt   exact request bytes as FC.send() lays them out"
                    % nm)
    plan.append("  %s.json        params / blob / claims / all self-checks" % "A")
    plan.append("  manifest.json  identities, both regions, cross-cell diffs")
    plan.append("")
    plan.append("SEND WITH:  python region_replay_2x2.py --send "
                "--confirm SEND-REGION-REPLAY-2X2")
    open(os.path.join(d, "PLAN.txt"), "w").write("\n".join(plan) + "\n")
    for nm, v in everything.items():
        payload = {k: val for k, val in v.items()
                   if k not in ("blob",)}
        payload["raw_request"] = v["raw_request"]
        if "blob" in v:
            payload["blob_hex"] = v["blob"].hex()
        json.dump(payload, open(os.path.join(d, "%s.json" % nm), "w"), indent=1)
        with open(os.path.join(d, "%s.http.txt" % nm), "w",
                  newline="") as f:
            f.write(v["raw_request"])
    return d


# ===========================================================================
# main
# ===========================================================================
def main():
    ap_args = sys.argv[1:]
    send = "--send" in ap_args
    dry = "--dry" in ap_args or not send       # DRY IS THE DEFAULT

    def opt(name, default=None, cast=str):
        if name in ap_args:
            return cast(ap_args[ap_args.index(name) + 1])
        return default

    args = type("A", (), {})()
    args.cap_row = opt("--captured-row", 0, int)
    args.pid = opt("--pid", DEFAULT_PID, int)
    args.tid = opt("--tid", DEFAULT_TID, int)
    args.rounds = opt("--rounds", 1, int)
    args.lead = opt("--lead", 20, int)         # seconds of mint lead time
    args.second = opt("--sign-second", None, int)
    args.order = opt("--order", "G0,GF,A,C,B,D")
    args.shuffle = opt("--shuffle", None, int)
    args.no_remint = "--no-remint" in ap_args
    args.confirm = opt("--confirm", None)
    head_name = opt("--head", "first")
    head = TRUE_HEADS.get(head_name) or LEGACY_HEADS[head_name]

    if send and args.confirm != CONFIRM_TOKEN:
        print("REFUSING to send.\n"
              "  --send requires the literal confirmation token:\n"
              "      --confirm %s\n"
              "  (dry mode is the default: re-run WITHOUT --send)" % CONFIRM_TOKEN)
        return 2

    print("=" * 78)
    print("REGION-PROVENANCE 2x2   mode=%s" % ("SEND" if send else "DRY (sends nothing)"))
    print("=" * 78)
    verify_head_phase()
    print()

    gen = load_genuine()
    cap = load_captured_region(args.cap_row)
    print("=== corpus ===")
    print("  genuine control : %s  gps=%s  blob=%d B"
          % (gen["raw_query"][:40] + "...", gen["params"]["gps_adid"],
             len(gen["blob"])))
    print("  captured region : all_signings row %d (src=%s, sign second=%s, "
          "phase=%s)"
          % (cap["row"], cap["src"], cap["second"], cap["phase"]))
    print("     d0 %s..." % cap["d0"][:24].hex())
    print("     d2 %s    d4 %s..." % (cap["d2"].hex(), cap["d4"][:16].hex()))
    print("  head            : %-28s pid=%d tid=%d"
          % (str(list(head)), args.pid, args.tid))
    if cap["phase"] != "?" and head_name in TRUE_HEADS \
            and cap["phase"] != head_name:
        print("  !! CONFOUND: the captured region is a %s-phase region but the"
              % cap["phase"])
        print("     fresh region is minted in the %s phase.  Cells A/B and C/D"
              % head_name)
        print("     then differ in the seed AND the head phase, so a negative")
        print("     result would be uninterpretable.  Use --head %s (or"
              % cap["phase"])
        print("     --captured-row 9 for the %s-phase region) to isolate the seed."
              % cap["phase"])
    print()

    import uuid
    rounds_out, all_results = [], {}
    for rnd in range(1, args.rounds + 1):
        second = (args.second if args.second is not None
                  else int(time.time()) + args.lead)
        if args.rounds > 1:
            second += (rnd - 1) * 60
        gps_fresh = str(uuid.uuid4())
        auid_fresh = str(uuid.uuid4())
        tag = "round%d" % rnd
        print("=== ROUND %d  sign-second=%d ===" % (rnd, second))
        variants, controls, meta, fresh_reg = build_plan(
            gen, cap, second, gps_fresh, auid_fresh, head, args.pid, args.tid,
            cap["row"], args.rounds, args.order, args.shuffle,
            remint=not args.no_remint)

        for nm, v in variants.items():
            print("\n  %s  %-28s  all self-checks %s"
                  % (nm, v["desc"], "PASS" if v["checks"]["ok"] else "FAIL"))
        bad = [n for n, v in variants.items() if not v["checks"]["ok"]]
        if not args.no_remint:
            print("\n  remint byte-identical: %s"
                  % {n: v.get("remint_identical") for n, v in variants.items()})

        # ---- the differential that IS the experiment --------------------
        print("\n  === cross-cell differential (the experimental variable) ===")
        print("   all four cells share sign-second %d and the same header: %s"
              % (second, len({variants[n]["blob"][:16]
                               for n in variants}) == 1))
        for a, b, what in (("A", "C", "same id, CAPTURED vs FRESH region"),
                           ("A", "B", "same region, orig vs fresh id"),
                           ("C", "D", "same id type diff, FRESH region"),
                           ("A", "D", "diagonal")):
            d = _dword_diff(variants[a]["blob"], variants[b]["blob"])
            hdr_same = variants[a]["blob"][:16] == variants[b]["blob"][:16]
            print("    %s vs %s: %2d/48 dwords differ  header_same=%-5s  %s"
                  % (a, b, len(d), hdr_same, what))

        # ---- minimality vs the genuine envelope -------------------------
        print("\n  === minimality vs the GENUINE envelope (param level) ===")
        gp = gen["params"]
        for nm in ("A", "B", "C", "D"):
            p = variants[nm]["params"]
            added = sorted(set(p) - set(gp))
            removed = sorted(set(gp) - set(p))
            changed = sorted(k for k in set(p) & set(gp) if p[k] != gp[k])
            print("    %s: %d params  added=%s removed=%s changed=%s"
                  % (nm, len(p), added or "-", removed or "-", changed or "-"))
            if added or removed:
                print("       !! param SET differs from genuine — the signed "
                      "claim set would differ too; NOT a minimal delta")
        # the emitted query must differ from genuine ONLY in those params
        for nm in ("A", "B", "C", "D"):
            p = variants[nm]["params"]
            got = {k: v[0] for k, v in
                   urllib.parse.parse_qs(enc(p), keep_blank_values=True).items()}
            mism = {k: (gp.get(k), got.get(k)) for k in set(got) | set(gp)
                    if got.get(k) != gp.get(k)}
            print("    %s: query round-trip differs from genuine in %d param(s)"
                  " %s" % (nm, len(mism), sorted(mism)))

        order = [s.strip() for s in args.order.split(",") if s.strip()]
        if args.shuffle is not None:
            random.Random(args.shuffle).shuffle(order)
        print("\n  interleaved send order (%d reqs): %s"
              % (len(order), " -> ".join(order)))

        d = write_out(tag, variants, controls, meta, fresh_reg, second, args,
                      head)
        print("\n  READY -> %s" % d)
        for nm in order:
            src = variants.get(nm) or controls[nm]
            print("    %-3s %s" % (nm, os.path.join(d, "%s.http.txt" % nm)))
        print("    %s" % os.path.join(d, "manifest.json"))

        if not send:
            print("\n  DRY: nothing was sent.  Exact bytes are on disk above.")
            for nm in order:
                src = variants.get(nm) or controls[nm]
                print("\n  ---------------- %s : %s ----------------"
                      % (nm, (variants.get(nm) or controls[nm])["desc"]))
                print(src["raw_request"][:2000])
        rounds_out.append({"round": rnd, "second": second, "dir": d,
                           "order": order})
        all_results[tag] = {"variants": {n: {"desc": v["desc"],
                                             "ok": v["checks"]["ok"]}
                                         for n, v in variants.items()},
                            "controls": {n: c["desc"] for n, c in
                                         controls.items()}}

    json.dump({"rounds": rounds_out, "summary": all_results,
               "order": args.order, "head": list(head), "pid": args.pid,
               "tid": args.tid, "captured_row": args.cap_row,
               "mode": "send" if send else "dry"},
              open(os.path.join(OUTDIR, "plan.json"), "w"), indent=1)

    if not send:
        allok = all(v["checks"]["ok"] for v in variants.values())
        print("\n" + "=" * 78)
        print("DRY-RUN %s  — %d variants + 2 controls built and self-checked."
              % ("GREEN" if allok else "RED", len(variants)))
        print("Ready to send with:")
        print("  python region_replay_2x2.py --send --confirm %s" % CONFIRM_TOKEN)
        print("=" * 78)
        return 0 if allok else 1

    # ======================= LIVE PATH (gated) =============================
    print("\n=== LIVE: firing round 1 at second %d ===" % second)
    results = {}
    for i, nm in enumerate(order):
        src = variants.get(nm) or controls[nm]
        while time.time() < second - 0.05:
            time.sleep(0.2)
        st, body = FC.send(URL, src["params"] if not src.get("verbatim")
                           else gen["params"], src["blob"] if "blob" in src
                           else bytes.fromhex(src["blob_hex"]), "GET")
        results[nm] = {"status": st, "body": body}
        print("  %-3s %-8s %s" % (nm, st, (body or "")[:90].replace("\n", " ")))
        time.sleep(1.5)
    sc = score(results)
    print("\n=== BIT-FLIP-RELATIVE SCORING ===")
    print("  control G0 (verbatim genuine) = %s" % sc["control_G0"])
    print("  control GF (1-bit flip)      = %s" % sc["control_GF"])
    for r in sc["rows"]:
        print("  %-3s %-6s %-9s %s" % (r["cell"], r["http"], r["class"],
                                      r["verdict"]))
    json.dump({"results": results, "scoring": sc},
              open(os.path.join(OUTDIR, "round1_result.json"), "w"), indent=1)
    print("\nsaved %s" % os.path.join(OUTDIR, "round1_result.json"))
    return 0


if __name__ == "__main__":
    mp.freeze_support()
    raise SystemExit(main())
