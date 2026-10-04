"""decoder.py — invert the adj9 wire whitening and recover a blob's region.

See bodymodel.py for the measurement machinery and decoder.md for the
write-up.  This module is the top level: turn a captured 192-B blob back
into its 45-word region and check it against the materializer F.py.
"""
from __future__ import annotations

import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mint_pipeline as M          # noqa: E402
import F as FREg                  # noqa: E402
from bodymodel import (ACTIVE, DESC_POS, ZERO_REGION, Model,  # noqa: E402
                       BLOB_WORDS, BODY_WORDS, gf2_solve, NVAR)

SAMPLE_SEED = 12345

# the words F.py derives from the seed; these must come back consistent
FREE_WORDS = ("F5", "F6")          # inside the 64-dim kernel, freely settable


# ---------------------------------------------------------------------------
# corpus helpers
# ---------------------------------------------------------------------------
def corpus_descs(row):
    """The exact descriptor list of a captured corpus row."""
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    r = asg[row]
    out = []
    for bi in M.VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytes.fromhex(hx) if hx else b""
        out.append((len(data) // 4, 0, data))
    return out


def corpus_second(row):
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    return int(ph3[row]["second"])


def corpus_blob(row):
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    return bytes.fromhex(ph3[row]["blob"]) if "blob" in ph3[row] else None


# ---------------------------------------------------------------------------
# header
# ---------------------------------------------------------------------------
def header_hex(words4):
    return b"".join(struct.pack(">I", x) for x in words4).hex()


def find_second(blob, lo, hi):
    """Invert the 16-B header: the signing second in [lo, hi] (or None)."""
    want = bytes(blob)[:16].hex()
    for s in range(int(lo), int(hi) + 1):
        if M.make_header(s).hex() == want:
            return s
    return None


# ---------------------------------------------------------------------------
# top level: decode one blob
# ---------------------------------------------------------------------------
def decode(blob, model, kind=None, base_descs=None, claims=None,
           max_steps=60_000_000):
    """Return (region_words, seed, report) for one 192-B blob."""
    blob = bytes(blob)
    w = list(struct.unpack(">%dI" % BLOB_WORDS, blob))
    body = w[4:]
    rep = {"second": model.second, "kind": kind or model.kind,
           "header_ok": M.make_header(model.second).hex() == header_hex(w[:4]),
           "model_rank": model.rank, "model_nsamp": model.nsamp}
    sol = model.solve(body)
    if sol is None:
        return None, None, dict(rep, ok=False, why="GF(2) system inconsistent")
    rep["solve_rank"] = sol.pop("_rank")

    d2 = sol["S"]
    seed = int.from_bytes(struct.pack(">I", d2), "little")
    d4w = FREg._d4_words(seed)
    d0c = FREg._d0_words(d4w, head=M.DEVICE_SELECTORS)
    rep["seed"] = "%08x" % seed
    rep["F_d4"] = ["%08x" % v for v in d4w]
    rep["F_d0_2_3"] = ["%08x" % v for v in (d0c[2], d0c[3])]
    # the map is full rank (256) so the solve is unique; the recovered F4 /
    # T0 / T1 must be exactly what F.py derives from the recovered seed.
    rep["F_match_d4"] = (d4w[4] == sol["F4"])
    rep["F_match_d0"] = (d0c[2] == sol["T0"] and d0c[3] == sol["T1"])
    rep["F_match_d4_hi"] = (d4w[5] == sol["F5"] and d4w[6] == sol["F6"])
    rep["body_predict_match"] = model.predict(sol) == body
    rep["words"] = {k: "%08x" % v for k, v in sol.items() if k != "_rank"}
    d0 = [sol["W0"], sol["X"], sol["T0"], sol["T1"]] + list(d0c[4:])

    # re-mint the recovered region and compare all 192 bytes
    reg = {0: struct.pack(">36I", *d0), 2: struct.pack(">I", d2),
           4: struct.pack(">8I", *d4w)}
    if base_descs is None:
        descs, _ = M.build_descriptors(claims, kind or model.kind,
                                       reg[0], reg[2], reg[4])
    else:
        descs = list(base_descs)
        for bi, val in reg.items():
            p = DESC_POS[bi]
            descs[p] = (len(val) // 4, descs[p][1], val)
    rb, _ = M.finex_mint(descs, model.second, max_steps=max_steps)
    rep["remint_byte_exact"] = (bytes(rb) == blob)
    rep["remint_match_words"] = 48 - sum(
        1 for a, b in zip(struct.unpack(">%dI" % BLOB_WORDS, rb), w) if a != b)
    rep["ok"] = rep["remint_byte_exact"]
    return sol, seed, rep


# ---------------------------------------------------------------------------
# claims extraction from the capture log
# ---------------------------------------------------------------------------
def claims_from_capture(path=None):
    import re
    path = path or os.path.join(HERE, "win_capture", "module_win_capture.log")
    txt = open(path, encoding="utf-8", errors="replace").read()
    blocks = re.findall(
        r"###ADJ9_BEGIN type=sign_input[^\n]*\n(.*?)\n###ADJ9_END", txt, re.S)
    out = []
    for b in blocks:
        s = k = None
        for line in b.split("\n"):
            if line.startswith("map_toString="):
                s = line[len("map_toString="):].lstrip("{")
            elif line.startswith("key2_hex="):
                k = line[len("key2_hex="):]
        claims = {}
        for item in s.split(", "):
            kk, _, vv = item.partition("=")
            claims[kk] = vv
        out.append((claims, bytes.fromhex(k)))
    return out


if __name__ == "__main__":
    rows = claims_from_capture()
    print("captured signings:", len(rows))
    for i, (c, blob) in enumerate(rows):
        print("  %d %-12s blob %d B  claims %d  second %s"
              % (i, c.get("activity_kind"), len(blob), len(c),
                 find_second(blob, 1790341400, 1790341600)))
