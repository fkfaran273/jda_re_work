"""_sub_claims3_stage6r.py — R6 reduced: the BLOCK-frame matrix (D9 x magic
x tail = 30 frames) x 6 new-key bindings x 11 laws on the 4 representative
records (one per activity kind).  Law discovery needs only one record per
kind; a correct law matches every record, a wrong one none.  Full-30 sweep
is reserved for confirmation after a hit (_sub_claims3_mint_check.py).
"""
import json
import os
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import _sub_claims3_search as S1
from _sub_claims3_oracle_fixed import oracle_frames_fixed
from _sub_ios_claims2_oracle import validate_on_android_golds

RESULTS = {"stages": {}, "hits": []}
OUT = os.path.join(HERE, "_sub_claims3_stage6r_out.json")

TAILS = {
    "02+dev": lambda r: bytes([0x02]) + r["dev"],
    "01+00*16": lambda r: b"\x01" + b"\x00" * 16,
    "02+00*16": lambda r: b"\x02" + b"\x00" * 16,
    "01+dev": lambda r: b"\x01" + r["dev"],
    "06+dev": lambda r: b"\x06" + r["dev"],
    "07+dev": lambda r: b"\x07" + r["dev"],
    "dev+02": lambda r: r["dev"] + b"\x02",
    "0207+00*15": lambda r: b"\x02\x07" + b"\x00" * 15,
    "rec111_130": lambda r: r["rec"][111:130],
    "dev_only": lambda r: r["dev"],
}
D9S = {"zeros20": lambda r: b"\x00" * 20, "empty": lambda r: b"",
       "devpad": lambda r: r["dev"] + b"\x00" * 4}
MAGICS = {"0008": b"\x00\x08", "0100": b"\x01\x00"}


def main():
    ok, n = validate_on_android_golds()
    print("oracle harness on android golds: %d/%d" % (ok, n), flush=True)
    corpus = S1.load_corpus()
    by_kind = {}
    for r in corpus:
        by_kind.setdefault(r["kind"], []).append(r)
    reps = [by_kind[k][0] for k in ("session", "click", "attribution", "event")]
    opts = [S1.base_opts(np="body", auth="nosig"),
            S1.base_opts(np="dec", auth="nosig"),
            S1.base_opts(np="body", auth="nosig", os_name="sim"),
            S1.base_opts(np=None, auth="nosig"),
            S1.base_opts(np="body", auth="emptysig"),
            S1.base_opts(np="body", auth="nosig_ns")]
    laws = ["sorted_split", "sorted_one", "hint5_prefix", "hint5_suffix",
            "dict6_prefix", "dict6_suffix", "authhdr6_prefix",
            "authhdr6_suffix", "wire_order_end", "vocab_cluster",
            "cluster_prefix"]
    hits = []
    n = 0
    t0 = time.time()
    for r in reps:
        for dn in D9S:
            for mn in MAGICS:
                for tn in TAILS:
                    d9 = D9S[dn](r)
                    tail = TAILS[tn](r)
                    cl = []
                    meta = []
                    for opt in opts:
                        for ln in laws:
                            cl.append(S1.LAWS[ln](r, opt))
                            meta.append((ln, json.dumps(opt, sort_keys=True)))
                    arr = np.array(oracle_frames_fixed(r, cl, d9,
                                                       MAGICS[mn], tail))
                    n += len(cl)
                    for i in np.nonzero(arr)[0]:
                        h = {"file": r["file"], "kind": r["kind"],
                             "law": meta[int(i)][0],
                             "opt": meta[int(i)][1],
                             "frame": "%s|%s|%s" % (dn, mn, tn),
                             "claims": cl[int(i)].decode("latin1", "replace")}
                        hits.append(h)
                        RESULTS["hits"].append(h)
                        print("  *** HIT:", h, flush=True)
        print("  %s done (%d cand, %.0fs)" % (r["file"], n,
                                              time.time() - t0), flush=True)
    RESULTS["stages"]["6r_frames_x_newclaims_reps"] = {
        "n": n, "hits": hits,
        "note": "30 frames (D9 x magic x tail) x 6 bindings x 11 laws, "
                "4 representative records"}
    with open(OUT, "w") as f:
        json.dump(RESULTS, f, indent=1)
    print("[stage 6r] %d candidates, %d hits" % (n, len(hits)), flush=True)


if __name__ == "__main__":
    main()
