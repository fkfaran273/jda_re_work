"""_sub_claims3_stage8.py — stage 8: EXACT replication of the prior stage-B
subset space (2^18 membership masks x 5 endpoints x 4 tails x 2 pinned on
the session record = 10,485,760 candidates) on the FIXED length-grouped
oracle and the CR-fixed loader.  The prior negative for this space is
invalid (batching corruption).  No auth values are involved, so the old
run's non-auth property holds; only the oracle mattered.
"""
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
OUT = os.path.join(HERE, "_sub_claims3_stage8_out.json")
CHUNK = 8192


def main():
    corpus = S1.load_corpus()
    sess = [r for r in corpus if r["kind"] == "session"][0]
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
    hits = []
    n = 0
    t0 = time.time()
    for ep in ENDPOINT_VALS:
        val = dict(sess["val"])
        if ep is not None:
            val["endpoint"] = ep
        for tail in TAIL_CHOICES:
            for pinned in (ADJ_SIGNING_ID, None):
                for i0 in range(0, 1 << len(TOGGLE_KEYS), CHUNK):
                    claims = []
                    meta = []
                    for bits in range(i0, min(i0 + CHUNK,
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
                    arr = np.array(oracle_batch_fixed(sess, claims))
                    n += len(claims)
                    for i in np.nonzero(arr)[0]:
                        h = dict(meta[int(i)])
                        h["claims"] = claims[int(i)].decode("latin1",
                                                            "replace")
                        hits.append(h)
                        RESULTS["hits"].append(h)
                        print("  *** HIT:", h, flush=True)
        print("  stage8 ep=%r done (%d cand, %d hits, %.0fs)"
              % (ep, n, len(hits), time.time() - t0), flush=True)
        with open(OUT, "w") as f:
            json.dump(RESULTS, f, indent=1)
    RESULTS["stages"]["8_old_stage_b_rerun"] = {"n": n, "hits": hits}
    with open(OUT, "w") as f:
        json.dump(RESULTS, f, indent=1)
    print("[stage 8] %d candidates, %d hits" % (n, len(hits)), flush=True)


if __name__ == "__main__":
    main()
