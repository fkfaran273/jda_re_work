"""_sub_ios_claims2_search2.py — Stage C of the iOS claims hunt.

New structural knowledge vs Stage B (from the Android+iOS SDK sources and the
proven Android law):

  * The native signer input = wire body params (+ extraParams that the proven
    Android law shows are NOT claimed: endpoint, control_params).
  * The native signer itself INJECTS exactly one extra claims key:
    adj_verification = b64(key_cycle_xor('{"os_name":"<os>"}'))  — on Android
    it is the only map key not on the wire, and it sorts FIRST in the profile.
  * On the capture (an ios-simulator build) the signer's adj_verification is
    the 40-char value in the Authorization header; a device build would send
    the 24-char f("ios") value.  Both are tested, plus JSON/plain forms.

Space: (all 2^18 subsets of the non-base wire keys)
       x adj_verification value (4 forms incl. absent)
       x tail placement (4 choices for session_count/started_at)
       x pinned adj_signing_id (present-after-profile / absent)
on the session record 0144.
"""
import itertools
import json
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from _sub_ios_claims2_oracle import (
    load_corpus, oracle_batch, block2, ADJ_SIGNING_ID,
)
import _sub_ios_mint as m

OUT = json.load(open(os.path.join(HERE, "_sub_ios_claims2_out.json")))

corpus = load_corpus()
sess = [r for r in corpus if r["kind"] == "session"][0]
val0 = dict(sess["val"])

BASE_PROFILE = [k for k in ("app_token", "app_version", "created_at",
                            "device_name", "device_type", "environment",
                            "installed_at", "os_name", "os_version")
                if k in val0]
TOGGLE_KEYS = sorted(k for k in val0 if k not in BASE_PROFILE)
print("base profile (%d): %s" % (len(BASE_PROFILE), BASE_PROFILE))
print("toggle keys (%d): %s" % (len(TOGGLE_KEYS), TOGGLE_KEYS))

ADJ_V_HEADER = "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"   # f("ios-simulator")
ADJ_V_IOS = m.make_adj_verification("ios")               # f("ios")
ADJ_V_FORMS = [
    ("none", None),
    ("b64-sim", ADJ_V_HEADER),
    ("b64-ios", ADJ_V_IOS),
    ("json-ios", '{"os_name":"ios"}'),
]

TAIL_CHOICES = [(), ("session_count",), ("started_at",),
                ("session_count", "started_at")]
PINNED_CHOICES = [ADJ_SIGNING_ID, None]


def build(val, prof_keys, tail_keys, pinned):
    parts = []
    for k in sorted(prof_keys):
        v = val.get(k)
        if v:
            parts.append(v)
    if pinned:
        parts.append(pinned)
    for k in sorted(tail_keys):
        v = val.get(k)
        if v:
            parts.append(v)
    parts.append(block2("session"))
    return "".join(parts).encode("latin1")


hits = []
total = 0
chunk = 65536
for adjv_name, adjv in ADJ_V_FORMS:
    for tail in TAIL_CHOICES:
        for pinned in PINNED_CHOICES:
            # precompute the non-toggle part of the value list
            for lo in range(0, 1 << len(TOGGLE_KEYS), chunk):
                hi = min(lo + chunk, 1 << len(TOGGLE_KEYS))
                batch = []
                for bits in range(lo, hi):
                    prof = list(BASE_PROFILE)
                    for i, k in enumerate(TOGGLE_KEYS):
                        if (bits >> i) & 1:
                            prof.append(k)
                    if adjv is not None:
                        prof.append("adj_verification")
                    prof = [k for k in prof if k not in tail]
                    val = val0
                    if adjv is not None:
                        val = dict(val0)
                        val["adj_verification"] = adjv
                    batch.append(build(val, prof, tail, pinned))
                res = oracle_batch(sess, batch)
                total += len(batch)
                for j, ok in enumerate(res):
                    if ok:
                        bits = lo + j
                        mask = [k for i, k in enumerate(TOGGLE_KEYS)
                                if (bits >> i) & 1]
                        hits.append({"adj_verification": adjv_name,
                                     "tail": list(tail), "pinned": pinned,
                                     "mask": mask,
                                     "claims": batch[j].decode("latin1")})
            print("  done adjv=%s tail=%s pinned=%r (cumulative %d)"
                  % (adjv_name, list(tail), pinned, total))

print("Stage C: %d candidates -> %d hits" % (total, len(hits)))
OUT["stage_c"] = {"n": total, "hits": hits}
with open(os.path.join(HERE, "_sub_ios_claims2_out.json"), "w") as f:
    json.dump(OUT, f, indent=1)
print("wrote _sub_ios_claims2_out.json")
