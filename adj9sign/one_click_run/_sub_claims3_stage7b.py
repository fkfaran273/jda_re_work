"""_sub_claims3_stage7b.py — stage 7b: the AUTH-BOUND membership bindings of
stage 7, re-run on the CR-fixed loader (the first stage-7 pass captured a
trailing \\r into the Authorization value, poisoning every auth-bound
candidate).  Non-auth bindings were valid there and are not repeated.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import _sub_claims3_search as S1
import _sub_claims3_stage78 as S78

RESULTS = S78.RESULTS
RESULTS["stages"] = {}
RESULTS["hits"] = []
S78.OUT = os.path.join(HERE, "_sub_claims3_stage7b_out.json")


def main():
    corpus = S1.load_corpus()
    by_kind = {}
    for r in corpus:
        by_kind.setdefault(r["kind"], []).append(r)
    reps = {k: by_kind[k][0] for k in ("session", "click", "attribution",
                                       "event")}
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
        toggle = [k for k in sorted(rec["val"]) if k not in FIXED and k != ""]
        if len(toggle) > 16:
            keep = ["primary_dedupe_token", "installed_at",
                    "needs_response_details", "idfa",
                    "initiated_by", "attribution_token"][:len(toggle) - 16]
            for k in keep:
                if k in toggle:
                    toggle.remove(k)
        print("stage7b %s: 2^%d masks" % (kind, len(toggle)), flush=True)
        tails = {"session": ["session_count"], "click": ["session_count"],
                 "event": ["session_count", "seq"],
                 "attribution": []}[kind]
        binds = [resolve(rec, b) for b in BIND_SPECS]
        n, h = S78.stage7(rec, toggle, FIXED, tails, binds,
                          ["sorted_split", "sorted_one"])
        total7 += n
        hits7 += h
        RESULTS["stages"]["7b_%s" % kind] = {"n": n, "hits": h}
        S78.save()
    print("[stage 7b] %d candidates, %d hits" % (total7, len(hits7)),
          flush=True)
    S78.save()


if __name__ == "__main__":
    main()
