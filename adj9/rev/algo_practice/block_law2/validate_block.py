"""validate_block.py — the block law's validation gate.

Sets:
  A) VM probes r0..r5                       (algo_practice/probes/*.json)
  B) 6 genuine penti winning blobs          (rev/win_capture/*)
  C) creditsea gold pairs                   (rev/creditsea/*)

Run: python validate_block.py
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALG = os.path.dirname(HERE)
REV = os.path.dirname(ALG)
CS = os.path.join(REV, "creditsea")
sys.path[:0] = [HERE, ALG, REV, CS]

import predict_block as PB                        # noqa: E402
from whiten_decoder import whiten_body_inverse, head_words   # noqa: E402
from desc10_law import build_desc10               # noqa: E402
from desc10_58 import build_desc10_58             # noqa: E402
from probe_runs import BASE_CLAIMS, RUNS          # noqa: E402
import F as FP                                    # noqa: E402

KINDS = ("session", "click", "attribution")


def record_of(blob):
    return whiten_body_inverse(blob[16:160], blob[:16])


def claim_candidates(v):
    """desc10 (#10) payload under both the 5.7.0 and the 5.8.0 claims laws."""
    kind = v.get("activity_kind", "session")
    if kind not in KINDS:
        kind = "session"
    out = []
    for name, fn in (("5.7.0", build_desc10), ("5.8.0", build_desc10_58)):
        try:
            r = fn(v, kind)
            out.append((name, r.encode("latin1") if isinstance(r, str) else r))
        except KeyError:
            pass
    return out


# --------------------------------------------------------------- set A
def set_probes():
    out = []
    for tag, sec, seed, tweak in RUNS:
        d = json.load(open(os.path.join(ALG, "probes", "run_%s.json" % tag)))
        claims = dict(BASE_CLAIMS)
        claims.update(tweak)
        cb = build_desc10(claims, "session").encode("latin1")
        d0w, _, _ = FP.region(seed, 0, 0, head=(0x2B, 0x48))
        got = PB.predict_block(cb, seed, head_words(d0w), PB.D9)
        out.append((tag, got, bytes.fromhex(d["block_hex"]), "5.7.0"))
    return out


# --------------------------------------------------------------- set B
def set_wins():
    lines = open(os.path.join(REV, "win_capture", "module_win_capture.log"),
                 encoding="utf-8", errors="replace").read().split("\n")
    si = [i for i, l in enumerate(lines)
          if l.startswith("###ADJ9_BEGIN type=sign_input")]
    ah = [i for i, l in enumerate(lines)
          if l.startswith("###ADJ9_BEGIN type=authorization_header")]
    out = []
    for n, (i, j) in enumerate(zip(si, ah)):
        v = {}
        for k in range(i, i + 10):
            if lines[k].startswith("map_order="):
                for p in lines[k][len("map_order="):].split("\x02"):
                    if "\x01" in p:
                        kk, vv = p.split("\x01", 1)
                        v[kk] = vv
                break
        blob = base64.b64decode(
            re.search(r'signature="([A-Za-z0-9+/=]+)"', lines[j + 2]).group(1))
        rec = record_of(blob)
        tgt = rec[46:78]
        cands = claim_candidates(v)
        got, which = None, ""
        for name, cb in cands:
            g = PB.predict_block(cb, int.from_bytes(rec[20:24], "big"),
                                 rec[3:19], rec[25:45])
            if g == tgt:
                got, which = g, name
                break
        if got is None and cands:
            got = PB.predict_block(cands[0][1],
                                   int.from_bytes(rec[20:24], "big"),
                                   rec[3:19], rec[25:45])
        out.append(("win%d" % n, got, tgt, which))
    return out


# --------------------------------------------------------------- set C
def set_creditsea():
    gs = json.load(open(os.path.join(CS, "gold_session.json")))
    gv = json.load(open(os.path.join(CS, "gold_vectors.json")))
    out = []
    for n, g in enumerate(gv):
        rec = record_of(bytes.fromhex(g["blob_hex"]))
        if g["second"] != gs["second"]:
            out.append(("gold%d" % n, None, rec[46:78],
                        "no claims map stored for this vector"))
            continue
        got, which = None, ""
        for name, cb in claim_candidates(gs["map"]):
            g2 = PB.predict_block(cb, int.from_bytes(rec[20:24], "big"),
                                  rec[3:19], rec[25:45])
            if g2 == rec[46:78]:
                got, which = g2, name
                break
        out.append(("gold%d" % n, got, rec[46:78], which))
    return out


def report(name, rows):
    ok = n = 0
    print("\n== %s ==" % name)
    for tag, got, want, note in rows:
        if got is None:
            print("  %-14s SKIP  %s" % (tag, note))
            continue
        good = got == want
        n += 1
        ok += good
        print("  %-14s %-4s %-6s got=%s" % (tag, "OK" if good else "FAIL",
                                           note or "", got.hex()))
        if not good:
            print("  %-14s      want=%s" % ("", want.hex()))
    print("  -> %d/%d byte-exact" % (ok, n))
    return ok, n


if __name__ == "__main__":
    to, tn = report("A) VM probes r0..r5", set_probes())
    bo, bn = report("B) genuine penti wins", set_wins())
    co, cn = report("C) creditsea gold", set_creditsea())
    print("\nTOTAL: probes %d/%d, wins %d/%d, creditsea %d/%d"
          % (to, tn, bo, bn, co, cn))
    sys.exit(0 if to == tn and bo == bn and co == cn else 1)
