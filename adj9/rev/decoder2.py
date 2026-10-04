"""decoder2.py — the taint-route body-decoder harness (adj9).

Top-level entry points (all offline; nothing existing is modified):

  python decoder2.py --winners
      Extract the 6 genuine winning blobs from win_capture/module_win_capture.log
      (base64 -> 192 B) and recover their signing seconds by header inversion
      (1790341508..1513 measured).  Dumps decoder2_winners.json.

  python decoder2.py --generativity
      Test the proposed seed-generativity law S = V ^ (pid16<<16),
      V = (sec' ± 2) ^ us', us' < 1e6, pid16 < 0x8000 against the four
      GENUINE device-captured seeds in win_capture/win_rows.json (the only
      signings whose S the device oracle has exposed).  Verdict: REFUTED —
      no consistent pid16 exists across rows 1+2 (same process, same
      second), and rows 3+4 admit no decomposition at all.

  python decoder2.py --taint [row]
      Run the vm_taint provenance tracker on a corpus row (default 7),
      verify the re-emitted blob is byte-exact, and dump the per-word
      derivation DAGs (taint_rowN_dags.json).

  python decoder2.py --validate [rows]
      Corpus validation driver: for each row, run the fin_vm2 forward mint
      against the captured blob (48/48 check) and the GF(2) linear-model
      solve (documented failure: system inconsistent), then report.

  python decoder2.py --probe blobhex claims_json second S
      Verify a candidate seed S against a captured blob by reminting the
      region with F.py and running the full forward encoder; prints the
      48-word match count.  (The 2^32 search this closes is the documented
      blocker — see decoder2.md §2.)

The decoder state of the art (decoder2.md):
  * body[i] = plain[i] ^ K_i, K = self-keyed feedback chain over KNOWN
    plaintext bytes; the seed words act through the index/branch machinery
    (udiv/msub/CAP schedule), so per-word value inversion and GF(2) both
    fail.  Recovery of (W0,X,T0,T1,F4,S) from a blob alone is blocked;
    on-device capture of S (win_rows.json hook shape) is the unblock.
"""
from __future__ import annotations

import base64
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from header_gen import make_header                       # noqa: E402
import decoder as D                                      # noqa: E402 (loaders)
import mint_pipeline as M                                # noqa: E402


def winners():
    rows = D.claims_from_capture()
    out = []
    for i, (claims, blob) in enumerate(rows):
        sec = None
        for s in range(1790341400, 1790341600):
            if make_header(s).hex() == blob[:16].hex():
                sec = s
                break
        out.append({"i": i, "kind": claims.get("activity_kind"),
                    "second": sec, "blob": blob.hex(),
                    "claims": claims})
        print("winner %d kind=%-12s second=%s claims=%d"
              % (i, claims.get("activity_kind"), sec, len(claims)))
    json.dump(out, open(os.path.join(HERE, "decoder2_winners.json"), "w"))
    print("wrote decoder2_winners.json")


def generativity():
    path = os.path.join(HERE, "win_capture", "win_rows.json")
    d = json.load(open(path))
    rows = d["rows"]
    print("=== S = V ^ (pid16<<16), V = sec' ^ us', sec' in sec+-2, "
          "us' < 1e6, pid16 < 0x8000 ===")
    table = []
    for r in rows:
        S, sec = int(r["S"]), int(r["second"])
        cands = []
        for ds in (-2, -1, 0, 1, 2):
            sp = sec + ds
            us_lo = (S & 0xFFFF) ^ (sp & 0xFFFF)
            for u_hi in range(16):                 # us' < 1e6 => us'>>16 <= 15
                us = us_lo + (u_hi << 16)
                if us >= 1_000_000:
                    continue
                V = (sp ^ us) & 0xFFFFFFFF
                pid16 = (S >> 16) ^ (sp >> 16) ^ u_hi
                if pid16 < 0x8000:
                    cands.append({"sec_off": ds, "us": us, "pid16": pid16,
                                  "V": "%08x" % V})
        ok = bool(cands)
        table.append({"sign_id": r["sign_id"], "second": sec,
                      "S": "%08x" % S, "decompositions": cands, "ok": ok})
        pids = sorted({c["pid16"] for c in cands})
        print("row sign_id=%d sec=%d S=%08x -> %s  pids=%s"
              % (r["sign_id"], sec, S, "OK" if ok else "NO DECOMPOSITION",
                 pids))
    # cross-row consistency (same process => same pid16)
    pids = None
    consistent = True
    for t in table:
        p = {c["pid16"] for c in t["decompositions"]}
        if pids is None:
            pids = set(p)
        else:
            pids &= p
    consistent = bool(pids)
    print("shared pid16 across rows: %s %s" % (consistent, sorted(pids) if
                                               pids else ""))
    print("VERDICT: %s" % ("GENERATIVE (shared pid16)"
                           if consistent else
                           "REFUTED — seeds are per-call /dev/urandom "
                           "entropy (the pid<<16 form is the emulator's "
                           "get8random FALLBACK only)"))
    json.dump(table, open(os.path.join(HERE, "decoder2_generativity.json"),
                          "w"), indent=1)
    return consistent


def taint(row=7):
    import vm_taint as T
    descs = T.corpus_row_descs(row)
    second, cap = T.corpus_row(row)
    t0 = time.time()
    ex, tn, st = T.run_taint(second, descs, T.default_seednames())
    words, stream = T.blob_words(ex, second, tn)
    ok = words is not None and \
        b"".join(struct.pack(">I", w[0] & T.M32) for w in words) == cap
    print("row %d status=%s steps=%d blob_match=%s (%.0fs)"
          % (row, st, ex.steps, ok, time.time() - t0))
    dump = {"row": row, "second": second, "blob": cap.hex(),
            "blob_match": ok, "words": {}}
    for i, (v, nd) in enumerate(words or []):
        if nd is None:
            continue
        dump["words"][str(i)] = {
            "value": "%08x" % (v & T.M32),
            "seeds": sorted(T.seed_set(nd)),
            "depth": T.depth(nd), "nnodes": T.nnodes(nd),
            "ops": T.op_hist(nd), "expr": T.fmt(nd)[:20000],
            "dag": T.prune(nd)}
    out = os.path.join(HERE, "taint_row%d_dags.json" % row)
    json.dump(dump, open(out, "w"))
    print("dumped", out)
    return ok


def validate(rows=(0, 1, 4, 5, 6, 7)):
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    ok_all = True
    for i in rows:
        descs = D.corpus_descs(i)
        sec = D.corpus_second(i)
        tgt = bytes.fromhex(ph3[i]["blob"])
        t0 = time.time()
        blob, info = M.finex_mint(descs, sec, max_steps=60_000_000)
        n = sum(1 for a, b in zip(struct.unpack(">48I", blob),
                                  struct.unpack(">48I", tgt)) if a == b)
        print("row %d second=%d forward-mint %d/48 (%.0fs)"
              % (i, sec, n, time.time() - t0))
        ok_all &= (n == 48)
    print("corpus forward-mint: %s" % ("PASS" if ok_all else "FAIL"))
    rep = os.path.join(HERE, "decoder_corpus.json")
    if os.path.exists(rep):
        r7 = json.load(open(rep)).get("7")
        if r7:
            print("GF(2) linear-model state on row 7: %s (rank %s) — the "
                  "documented non-linearity"
                  % (r7.get("why") or ("ok" if r7.get("ok") else "?"),
                     r7.get("model_rank")))
    return ok_all


def probe(blobhex, claims_json, second, seed):
    """Remint with F.py(region(seed)) and compare against the blob."""
    claims = json.loads(claims_json)
    seed = int(seed, 0)
    kind = claims.get("activity_kind", "session")
    d0, d2, d4 = M.resolve_region(seed, M.DEFAULT_PID, M.DEFAULT_TID,
                                  head=M.head_for_endpoint(kind))
    descs, _ = M.build_descriptors(claims, kind, d0, d2, d4)
    blob, info = M.finex_mint(descs, int(second), max_steps=60_000_000)
    tgt = bytes.fromhex(blobhex)
    n = sum(1 for a, b in zip(struct.unpack(">48I", blob),
                              struct.unpack(">48I", tgt)) if a == b)
    print("seed %08x -> %d/48 words (hdr %d/4)"
          % (seed, n, sum(1 for a, b in zip(blob[:4], tgt[:4]) if a == b)))
    return n == 48


def main():
    a = sys.argv[1:]
    if "--winners" in a:
        winners()
    elif "--generativity" in a:
        generativity()
    elif "--taint" in a:
        taint(int(a[a.index("--taint") + 1]) if len(a) > 2 else 7)
    elif "--validate" in a:
        rows = (0, 1, 4, 5, 6, 7)
        if len(a) > 2:
            rows = tuple(int(x) for x in a[2].split(","))
        validate(rows)
    elif "--probe" in a:
        i = a.index("--probe")
        probe(a[i + 1], a[i + 2], a[i + 3], a[i + 4])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
