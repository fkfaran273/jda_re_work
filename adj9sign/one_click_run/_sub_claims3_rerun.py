"""_sub_claims3_rerun.py — re-run ALL claims3 stages (1-6) with the FIXED
length-grouped BLOCK oracle (the previous batches corrupted every row
shorter than the batch max — forged-hit proof in _sub_claims3_oracle_fixed).
Then stage 7 (membership subsets x new-key bindings) and stage 8 (exact
replication of the prior stage-B subset space, previously corrupted).
"""
import itertools
import json
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import _sub_claims3_search as S1
import _sub_claims3_search2 as S2
from _sub_claims3_oracle_fixed import oracle_batch_fixed, \
    oracle_frames_fixed
from _sub_ios_claims2_oracle import validate_on_android_golds

RESULTS = {"stages": {}, "hits": []}
OUT = os.path.join(HERE, "_sub_claims3_out.json")


def save():
    with open(OUT, "w") as f:
        json.dump(RESULTS, f, indent=1)


def run_stage(name, records, opts, laws, note="", oracle=None):
    if oracle is None:
        oracle = oracle_batch_fixed
    n = 0
    hits = []
    for r in records:
        claims_list = []
        meta = []
        for opt in opts:
            for ln in laws:
                claims_list.append(laws[ln](r, opt) if isinstance(laws, dict)
                                   else S1.LAWS[ln](r, opt))
                meta.append((ln, json.dumps(opt, sort_keys=True)))
        for i0 in range(0, len(claims_list), 40000):
            chunk = claims_list[i0:i0 + 40000]
            arr = np.array(oracle(r, chunk))
            n += len(chunk)
            for i in np.nonzero(arr)[0]:
                gi = i0 + int(i)
                h = {"file": r["file"], "kind": r["kind"],
                     "law": meta[gi][0], "opt": meta[gi][1],
                     "claims": chunk[i].decode("latin1", "replace")}
                hits.append(h)
                RESULTS["hits"].append(h)
                print("  *** HIT:", h, flush=True)
    RESULTS["stages"][name] = {"n": n, "hits": hits, "note": note}
    print("[stage %s] %d candidates, %d hits" % (name, n, len(hits)),
          flush=True)
    save()
    return hits


def bo(**kw):
    return S1.base_opts(**kw)


def main():
    ok, n = validate_on_android_golds()
    print("oracle harness on android golds: %d/%d" % (ok, n), flush=True)
    g, p = __import__("_sub_claims3_oracle_fixed").selftest()
    print("fixed oracle: golds %d/9, positive controls %d/2" % (g, p),
          flush=True)
    corpus = S1.load_corpus()
    by_kind = {}
    for r in corpus:
        by_kind.setdefault(r["kind"], []).append(r)
    reps = [by_kind[k][0] for k in ("session", "click", "attribution", "event")]

    L1 = S1.LAWS
    L2 = S2.LAWS5

    # ---- re-run search1 stages with fixed oracle ----
    opts1 = [bo(np=np_m, auth=au, os_name=osn)
             for np_m in (None, "body", "dec")
             for au in (None, "nosig", "emptysig", "nosig_ns")
             for osn in ("wire", "sim")]
    run_stage("R1_fixed_laws", corpus, opts1,
              ["sorted_split", "sorted_one", "wire_order_end"],
              note="rerun of stage1 with fixed oracle")

    opts2 = [bo(np="body", auth="nosig"),
             bo(np="body", auth="nosig", os_name="sim"),
             bo(np=None, auth="nosig"),
             bo(np="body", auth=None),
             bo(np=None, auth=None, os_name="sim"),
             bo(np="dec", auth="nosig"),
             bo(np="body", auth="emptysig"),
             bo(np="body", auth="nosig", secret="empty"),
             bo(np="body", auth="nosig", sig="empty"),
             bo(np="body", auth="nosig", env="sandbox"),
             bo(np="bodyquery", auth="nosig"),
             bo(np="target", auth="nosig"),
             bo(np="query", auth="nosig"),
             bo(np="body", auth="full"),
             bo(np="body", auth="nosig", sig="cap"),
             bo(np="body", auth="nosig", secret="1500000"),
             bo(np="body", auth="nosig", secret="10"),
             bo(np="body", auth="nosig", secret="one"),
             bo(np="body", auth="nosig", endpoint="path"),
             bo(np="body", auth="nosig", adjv="ios")]
    run_stage("R2_orders", corpus, opts2,
              ["hint5_prefix", "hint5_suffix", "dict6_prefix", "dict6_suffix",
               "cluster_prefix", "cluster_suffix", "authhdr6_prefix",
               "authhdr6_suffix", "wire_order_front"],
              note="rerun of stage2 with fixed oracle")

    opts3 = [bo(np=np_m, auth=au, os_name=osn)
             for np_m in (None, "body") for au in (None, "nosig")
             for osn in ("wire", "sim")]
    run_stage("R3_vocab_only", corpus, opts3,
              ["vocab_cluster", "vocab_sorted", "vocab_sorted_split"],
              note="rerun of stage3 with fixed oracle")

    opts4 = [bo(np=np_m, auth=au, sig=sig, env=env, os_name=osn,
                secret=sec, endpoint=ep)
             for np_m in (None, "body", "dec", "bodyquery", "target", "query")
             for au in (None, "nosig", "emptysig", "nosig_ns", "full")
             for sig in (None, "empty", "cap")
             for env in ("production", "sandbox", "Production", "Sandbox")
             for osn in ("wire", "sim")
             for sec in (None, "empty", "1500000", "10", "one")
             for ep in ("base", "path")]
    run_stage("R4_combinatorial_reps", reps, opts4,
              ["sorted_split", "sorted_one", "wire_order_end",
               "hint5_prefix", "hint5_suffix", "dict6_prefix", "dict6_suffix",
               "cluster_prefix", "cluster_suffix", "authhdr6_prefix",
               "authhdr6_suffix", "wire_order_front", "vocab_cluster",
               "vocab_sorted", "vocab_sorted_split"],
              note="rerun of stage4 with fixed oracle")

    # ---- re-run search2 stages with fixed oracle ----
    opts5a = [bo(np=np_m, auth=au, os_name=osn, adjv=av, alg=alg)
              for np_m in (None, "body", "dec")
              for au in ("nosig", "emptysig", "nosig_ns")
              for osn in ("wire", "sim")
              for av in ("cap", "ios")
              for alg in (None, "adj9")]
    run_stage("R5a_full_lists", corpus, opts5a,
              {**{k: L1[k] for k in ("sorted_split", "sorted_one",
                                     "wire_order_end", "wire_order_front",
                                     "hint5_prefix", "hint5_suffix",
                                     "dict6_prefix", "dict6_suffix",
                                     "cluster_prefix", "cluster_suffix",
                                     "authhdr6_prefix", "authhdr6_suffix",
                                     "vocab_cluster", "vocab_sorted_split")},
               **{k: L2[k] for k in ("canonical_split", "canonical_one",
                                     "kv_amp_sorted", "val_amp",
                                     "len4_sorted", "np_hash_sha256hex",
                                     "inj_sorted", "auth_only", "np_only",
                                     "json_compact")}},
              note="rerun of 5a + key 5e-5h laws with fixed oracle, all 30")

    # ---- re-run stage 6 (frames) with FIXED generic oracle ----
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

    def run_stage6(name, records, opts, law_names, note=""):
        n = 0
        hits = []
        for r in records:
            for dn in D9S:
                for mn in MAGICS:
                    for tn in TAILS:
                        d9 = D9S[dn](r)
                        tail = TAILS[tn](r)
                        cl = []
                        meta = []
                        for opt in opts:
                            for ln in law_names:
                                cl.append(L1[ln](r, opt))
                                meta.append((ln, json.dumps(opt,
                                                            sort_keys=True)))
                        arr = np.array(oracle_frames_fixed(
                            r, cl, d9, MAGICS[mn], tail))
                        n += len(cl)
                        for i in np.nonzero(arr)[0]:
                            h = {"file": r["file"], "kind": r["kind"],
                                 "law": meta[int(i)][0], "opt": meta[int(i)][1],
                                 "frame": "%s|%s|%s" % (dn, mn, tn),
                                 "claims": cl[int(i)].decode("latin1",
                                                             "replace")}
                            hits.append(h)
                            RESULTS["hits"].append(h)
                            print("  *** HIT:", h, flush=True)
        RESULTS["stages"][name] = {"n": n, "hits": hits, "note": note}
        print("[stage %s] %d candidates, %d hits" % (name, n, len(hits)),
              flush=True)
        save()
        return hits

    opts6 = [bo(np="body", auth="nosig"),
             bo(np="dec", auth="nosig"),
             bo(np="body", auth="nosig", os_name="sim"),
             bo(np=None, auth="nosig"),
             bo(np="body", auth="emptysig"),
             bo(np="body", auth="nosig_ns")]
    run_stage6("R6_frames_x_newclaims", corpus, opts6,
               ["sorted_split", "sorted_one", "hint5_prefix", "hint5_suffix",
                "dict6_prefix", "dict6_suffix", "authhdr6_prefix",
                "authhdr6_suffix", "wire_order_end", "vocab_cluster",
                "cluster_prefix"],
               note="rerun of stage6 with fixed generic-frame oracle")

    total = sum(s["n"] for s in RESULTS["stages"].values())
    print("TOTAL rerun R1-R6: %d candidates, %d hits" % (total, len(hits)),
          flush=True)
    save()


if __name__ == "__main__":
    main()
