"""_sub_claims3_stage78.py — stage 7 (membership subsets x new-key bindings)
and stage 8 (EXACT replication of the prior stage-B subset space —
_sub_ios_claims2_search.py Stage B: 2^18 membership masks x 5 endpoints x
4 tails x 2 pinned on the session record = 10,485,760 candidates) — both on
the FIXED length-grouped oracle.  The prior run of this exact space was
invalidated by the mixed-length batching bug.
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
from _sub_ios_claims2_oracle import build_claims, ADJ_SIGNING_ID

RESULTS = {"stages": {}, "hits": []}
OUT = os.path.join(HERE, "_sub_claims3_stage78_out.json")

CHUNK_MASKS = 8192


def save():
    with open(OUT, "w") as f:
        json.dump(RESULTS, f, indent=1)


def check(rec, claims, hits, meta, total_ref):
    arr = np.array(oracle_batch_fixed(rec, claims))
    for i in np.nonzero(arr)[0]:
        h = dict(meta[int(i)])
        h["claims"] = claims[int(i)].decode("latin1", "replace")
        hits.append(h)
        RESULTS["hits"].append(h)
        print("  *** HIT:", h, flush=True)


def stage7(rec, toggle_keys, fixed_profile, tail_keys, bindings, laws,
           pinned_choices=(ADJ_SIGNING_ID, None)):
    """membership subsets over toggle_keys with injected-value bindings."""
    hits = []
    n = 0
    t0 = time.time()
    for bopt in bindings:
        val = dict(rec["val"])
        for k, v in bopt.items():
            if v is not None:
                val[k] = v
        prof_fixed = [k for k in fixed_profile if k in val]
        prof_fixed += [k for k, v in bopt.items()
                       if v is not None and k in ("network_payload",
                                                  "authorization")]
        for law in laws:
            for pinned in pinned_choices:
                for i0 in range(0, 1 << len(toggle_keys), CHUNK_MASKS):
                    claims = []
                    meta = []
                    for bits in range(i0, min(i0 + CHUNK_MASKS,
                                              1 << len(toggle_keys))):
                        prof = list(prof_fixed)
                        for j, k in enumerate(toggle_keys):
                            if bits >> j & 1:
                                prof.append(k)
                        if law == "sorted_split":
                            c = build_claims(val, prof, list(tail_keys),
                                             rec["kind"], pinned=pinned)
                        else:  # sorted_one: everything one sorted run
                            pool = {k: val[k] for k in prof + list(tail_keys)}
                            keys = sorted(pool)
                            parts = []
                            pd = False
                            for k in keys:
                                if not pd and pinned and k > "adj_signing_id":
                                    parts.append(ADJ_SIGNING_ID)
                                    pd = True
                                parts.append(pool[k])
                            if pinned and not pd:
                                parts.append(ADJ_SIGNING_ID)
                            parts.append(rec["kind"] + "ios5.8.0" + "10"
                                         + "5.0.0")
                            c = "".join(parts).encode("latin1")
                        claims.append(c)
                        meta.append({"file": rec["file"], "kind": rec["kind"],
                                     "law": law, "pinned": pinned,
                                     "binding": json.dumps(bopt,
                                                           sort_keys=True),
                                     "mask": bits})
                    check(rec, claims, hits, meta, n)
                    n += len(claims)
        print("  stage7 binding %s done (%d cand, %d hits, %.0fs)"
              % (json.dumps(bopt, sort_keys=True), n, len(hits),
                 time.time() - t0), flush=True)
    return n, hits


def main():
    corpus = S1.load_corpus()
    by_kind = {}
    for r in corpus:
        by_kind.setdefault(r["kind"], []).append(r)
    reps = {k: by_kind[k][0] for k in ("session", "click", "attribution",
                                       "event")}
    sess = reps["session"]

    # ---------------- stage 7 ----------------
    FIXED = ["app_token", "app_version", "app_version_short", "created_at",
             "device_name", "device_type", "environment", "os_name",
             "os_version", "bundle_id", "idfv", "sent_at"]
    BIND_SPECS = [(None, None, None), ("body", None, None),
                  (None, "nosig", None), ("body", "nosig", None),
                  ("body", None, "sim"), ("body", "nosig", "sim")]

    def resolve(rec, spec):
        np_m, au_m, os_m = spec
        out = {}
        if np_m == "body":
            out["network_payload"] = rec["raw_body"]
        if au_m == "nosig":
            out["authorization"] = S1.auth_variants(rec)["nosig"]
        if os_m == "sim":
            out["os_name"] = "ios-simulator"
        return out

    total7 = 0
    hits7 = []
    for kind, rec in reps.items():
        toggle = [k for k in sorted(rec["val"]) if k not in FIXED
                  and k != ""]
        # cap the toggle width for the big kinds by pinning high-priority keys
        if len(toggle) > 16:
            keep = ["primary_dedupe_token", "installed_at",
                    "needs_response_details", "idfa",
                    "initiated_by", "attribution_token"][:len(toggle) - 16]
            for k in keep:
                if k in toggle:
                    toggle.remove(k)
        print("stage7 %s: %d toggle keys -> 2^%d masks" % (kind, len(toggle),
                                                           len(toggle)),
              flush=True)
        tails = {"session": ["session_count"], "click": ["session_count"],
                 "event": ["session_count", "seq"],
                 "attribution": []}[kind]
        binds = [resolve(rec, b) for b in BIND_SPECS]
        n, h = stage7(rec, toggle, FIXED, tails, binds,
                      ["sorted_split", "sorted_one"])
        total7 += n
        hits7 += h
        RESULTS["stages"]["7_%s" % kind] = {"n": n, "hits": h}
        save()
    print("[stage 7] %d candidates, %d hits" % (total7, len(hits7)),
          flush=True)

    # ---------------- stage 8: exact prior stage-B replication ----------
    ENDPOINT_VALS = ["https://consent.adjust.io",
                     "https://consent.adjust.com",
                     "consent.adjust.io",
                     "https://consent.adjust.io/session",
                     None]
    TOGGLE_KEYS = [k for k in sorted(sess["val"]) if k not in
                   ("app_token", "app_version", "created_at", "device_name",
                    "device_type", "environment", "os_name", "os_version")]
    BASE_PROFILE = [k for k in ("app_token", "app_version", "created_at",
                                "device_name", "device_type", "environment",
                                "installed_at", "os_name", "os_version")
                    if k in sess["val"]]
    TAIL_CHOICES = [(), ("session_count",), ("started_at",),
                    ("session_count", "started_at")]
    hits8 = []
    n8 = 0
    t0 = time.time()
    for ep in ENDPOINT_VALS:
        val = dict(sess["val"])
        if ep is not None:
            val["endpoint"] = ep
        for tail in TAIL_CHOICES:
            for pinned in (ADJ_SIGNING_ID, None):
                for i0 in range(0, 1 << len(TOGGLE_KEYS), CHUNK_MASKS):
                    claims = []
                    meta = []
                    for bits in range(i0, min(i0 + CHUNK_MASKS,
                                              1 << len(TOGGLE_KEYS))):
                        prof = list(BASE_PROFILE)
                        for j, k in enumerate(TOGGLE_KEYS):
                            if bits >> j & 1:
                                prof.append(k)
                        claims.append(build_claims(val, prof, list(tail),
                                                   "session",
                                                   pinned=pinned))
                        meta.append({"file": sess["file"], "kind": "session",
                                     "law": "old_stage_b",
                                     "endpoint": ep, "tail": list(tail),
                                     "pinned": pinned, "mask": bits})
                    check(sess, claims, hits8, meta, n8)
                    n8 += len(claims)
        print("  stage8 ep=%r done (%d cand, %.0fs)" % (ep, n8,
                                                        time.time() - t0),
          flush=True)
    RESULTS["stages"]["8_old_stage_b_rerun"] = {"n": n8, "hits": hits8}
    print("[stage 8] %d candidates, %d hits" % (n8, len(hits8)), flush=True)
    save()
    total = total7 + n8
    print("TOTAL stages 7-8: %d candidates, %d hits"
          % (total, len(RESULTS["hits"])), flush=True)


if __name__ == "__main__":
    main()
