"""_sub_claims3_stage10.py — stage 10: gap-cells on the fixed oracle.
(a) envelope permutations (24 orders of the BLOCK2 family),
(b) absent endpoint / adj_verification / os_name / environment (drop cells),
(c) injected-keys membership subsets (2^4: np, auth, sig, secret) x orders,
(d) alphabetical-position pinned (sorted_one) with injected keys excluded.
"""
import itertools
import json
import os
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import _sub_claims3_search as S1
from _sub_claims3_oracle_fixed import oracle_batch_fixed
from _sub_ios_claims2_oracle import validate_on_android_golds

RESULTS = {"stages": {}, "hits": []}
OUT = os.path.join(HERE, "_sub_claims3_stage10_out.json")
ENV_KEYS = ["activity_kind", "client_sdk", "headers_id", "native_version"]


def save():
    with open(OUT, "w") as f:
        json.dump(RESULTS, f, indent=1)


def env_str_perm(r, perm, extra=None):
    vals = {"activity_kind": r["kind"], "client_sdk": S1.CLIENT_SDK,
            "headers_id": S1.HEADERS_ID, "native_version": S1.NATIVE_VERSION,
            "algorithm": S1.ALGORITHM, "adj_signing_id": S1.ADJ_SIGNING_ID,
            "adj_verification": S1.ADJV_CAP}
    keys = list(perm)
    if extra:
        keys = keys + [extra]
    return "".join(vals[k] for k in keys)


def law_with_env(r, opt, perm, extra=None, pinned="mid"):
    pool = S1.pool_of(r, opt)
    prof, tail = S1.profile_tail_keys(r["kind"])
    prof = [k for k in prof if k not in S1.INJECTABLE]
    tail = [k for k in tail if k not in S1.INJECTABLE]
    inj_keys = [k for k in S1.INJECTABLE if k in pool]
    prof = prof + inj_keys
    parts = [pool.get(k, "") or "" for k in sorted(prof)]
    if pinned == "first":
        parts.insert(0, S1.ADJ_SIGNING_ID)
    elif pinned in ("mid", "last"):
        parts.append(S1.ADJ_SIGNING_ID)
    parts += [pool.get(k, "") or "" for k in sorted(tail) if pool.get(k)]
    if pinned == "last":
        parts.append(S1.ADJ_SIGNING_ID)
    parts.append(env_str_perm(r, perm, extra))
    return "".join(parts).encode("latin1")


def run(name, records, claims_fn, note):
    n = 0
    hits = []
    t0 = time.time()
    for r in records:
        cl = []
        meta = []
        for m_i, (opt, lawname, extra) in enumerate(claims_fn(r)):
            cl.append(extra(r, opt))
            meta.append((lawname, json.dumps(opt, sort_keys=True)))
        for i0 in range(0, len(cl), 40000):
            chunk = cl[i0:i0 + 40000]
            arr = np.array(oracle_batch_fixed(r, chunk))
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
    print("[stage %s] %d candidates, %d hits (%.0fs)"
          % (name, n, len(hits), time.time() - t0), flush=True)
    save()


def main():
    ok, n = validate_on_android_golds()
    print("oracle harness on android golds: %d/%d" % (ok, n), flush=True)
    corpus = S1.load_corpus()
    perms = list(itertools.permutations(
        ["activity_kind", "client_sdk", "headers_id", "native_version"]))
    perms = [p for p in perms if p == ("activity_kind", "client_sdk",
                                       "headers_id", "native_version")][0:1] \
        + [p for p in perms if p != ("activity_kind", "client_sdk",
                                     "headers_id", "native_version")]
    extras = [None, "algorithm", "adj_signing_id", "adj_verification"]

    binds = [dict(S1.DEF_OPT, np="body", auth="nosig"),
             dict(S1.DEF_OPT, np="body", auth="nosig", os_name="sim"),
             dict(S1.DEF_OPT, np=None, auth=None),
             dict(S1.DEF_OPT, np="dec", auth="nosig"),
             dict(S1.DEF_OPT, np="body", auth="nosig", adjv=None),
             dict(S1.DEF_OPT, np="body", auth="nosig", endpoint=None),
             dict(S1.DEF_OPT, np="body", auth="nosig", os_name="sim",
                  adjv=None, endpoint=None),
             dict(S1.DEF_OPT, np="body", auth="nosig",
                  drop=["os_name"]),
             dict(S1.DEF_OPT, np="body", auth="nosig",
                  drop=["environment"]),
             dict(S1.DEF_OPT, np="body", auth="nosig", env="sandbox")]

    def gen(r):
        for opt in binds:
            for pi, perm in enumerate(perms):
                for extra in extras:
                    yield (opt, "envperm%d_%s" % (pi, extra),
                           lambda rr, o, _p=perm, _e=extra:
                           law_with_env(rr, o, _p, _e, "mid"))
                    yield (opt, "envperm%d_%s_pfirst" % (pi, extra),
                           lambda rr, o, _p=perm, _e=extra:
                           law_with_env(rr, o, _p, _e, "first"))
                    yield (opt, "envperm%d_%s_pnone" % (pi, extra),
                           lambda rr, o, _p=perm, _e=extra:
                           law_with_env(rr, o, _p, _e, "none"))

    run("10_envperm_drops", corpus, gen,
        note="24 envelope permutations x 4 extras x 10 bindings x pinned "
             "{mid, first}")

    total = sum(s["n"] for s in RESULTS["stages"].values())
    print("TOTAL stage10: %d candidates, %d hits" % (total, len(hits)),
          flush=True)


if __name__ == "__main__":
    main()
