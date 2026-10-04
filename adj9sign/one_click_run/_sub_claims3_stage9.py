"""_sub_claims3_stage9.py — stage 9: canonical-timestamp claims.

The closed core imports NSLocale en_US_POSIX + NSTimeZone(secondsFromGMT:0)
with dateFormat yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z' — canonical UTC second-
precision timestamps.  The wire datetimes carry millis + offset
(2026-08-23T23:34:25.244Z-0700).  Test claims where created_at/sent_at/
installed_at/started_at are REPLACED by canonical forms (the server can
re-derive them from the wire values), plus epoch/epoch-ms forms.
"""
import datetime
import json
import os
import re
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import _sub_claims3_search as S1
from _sub_claims3_oracle_fixed import oracle_batch_fixed
from _sub_ios_claims2_oracle import validate_on_android_golds

RESULTS = {"stages": {}, "hits": []}
OUT = os.path.join(HERE, "_sub_claims3_stage9_out.json")
DT_KEYS = ["created_at", "sent_at", "installed_at", "started_at"]
DT_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"
                   r"\.(\d+)Z([+-]\d{4})$")
FORMS = ["canonZ", "canonZ_ms", "epoch", "epoch_ms", "canonZ+0000",
         "spaceZ"]


def parse_dt(v):
    m = DT_RE.match(v)
    if not m:
        return None
    y, mo, d, h, mi, s, ms, off = m.groups()
    t = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s),
                          tzinfo=datetime.timezone.utc)
    offsign = 1 if off[0] == "+" else -1
    delta = offsign * (int(off[1:3]) * 3600 + int(off[3:5]) * 60)
    t = t - datetime.timedelta(seconds=delta)   # local -> UTC
    return t, int(ms)


def variants(v):
    p = parse_dt(v)
    if not p:
        return {}
    t, ms = p
    return {
        "canonZ": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "canonZ_ms": t.strftime("%Y-%m-%dT%H:%M:%S") + ".%03dZ" % ms,
        "epoch": str(int(t.timestamp())),
        "epoch_ms": str(int(t.timestamp()) * 1000 + ms),
        "canonZ+0000": t.strftime("%Y-%m-%dT%H:%M:%S+0000"),
        "spaceZ": t.strftime("%Y-%m-%d %H:%M:%SZ"),
    }


def save():
    with open(OUT, "w") as f:
        json.dump(RESULTS, f, indent=1)


def main():
    ok, n = validate_on_android_golds()
    print("oracle harness on android golds: %d/%d" % (ok, n), flush=True)
    corpus = S1.load_corpus()
    laws = ["sorted_split", "sorted_one", "hint5_prefix", "dict6_prefix",
            "authhdr6_prefix", "wire_order_end"]
    binds = [dict(S1.DEF_OPT),
             dict(S1.DEF_OPT, np="body", auth="nosig")]

    total = 0
    hits = []
    t0 = time.time()
    for r in corpus:
        dts = {k: r["val"][k] for k in DT_KEYS if k in r["val"]}
        if not dts:
            continue
        varmap = {k: variants(v) for k, v in dts.items()}
        claims_list = []
        meta = []
        for mask in range(1 << len(dts)):
            keys = [k for i, k in enumerate(dts) if mask >> i & 1]
            for form in FORMS:
                for opt in binds:
                    val = dict(r["val"])
                    for k in keys:
                        val[k] = varmap[k][form]
                    r2 = dict(r)
                    r2["val"] = val
                    for ln in laws:
                        claims_list.append(S1.LAWS[ln](r2, opt))
                        meta.append((ln, json.dumps(
                            {"dt_keys": keys, "form": form,
                             "bind": ("np+auth" if opt["np"] else "plain")},
                            sort_keys=True)))
        for i0 in range(0, len(claims_list), 40000):
            chunk = claims_list[i0:i0 + 40000]
            arr = np.array(oracle_batch_fixed(r, chunk))
            total += len(chunk)
            for i in np.nonzero(arr)[0]:
                gi = i0 + int(i)
                h = {"file": r["file"], "kind": r["kind"],
                     "law": meta[gi][0], "opt": meta[gi][1],
                     "claims": chunk[i].decode("latin1", "replace")}
                hits.append(h)
                RESULTS["hits"].append(h)
                print("  *** HIT:", h, flush=True)
        print("  %s done (%d cand total, %.0fs)"
              % (r["file"], total, time.time() - t0), flush=True)
    RESULTS["stages"]["9_timestamps"] = {"n": total, "hits": hits,
                                         "note": "canonical UTC / epoch "
                                                 "timestamp substitutions "
                                                 "x 6 laws x 2 bindings"}
    print("[stage 9] %d candidates, %d hits" % (total, len(hits)), flush=True)
    save()


if __name__ == "__main__":
    main()
