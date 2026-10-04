"""_sub_ios_claims2_search.py — the iOS claims-law search, driven by the
Adjust iOS SDK v5.8.0 signing-input structure.

Signer input (from ADJRequestHandler.m):
    mergedParameters = wire body params
    extraParams      = {client_sdk, activity_kind, endpoint} + control_params

Search space per record:
  * key pool   = wire params (+ optional extras: endpoint, synthesized keys)
  * membership = which pool keys the native law claims (toggled)
  * placement  = profile (sorted) / tail (sorted, after pinned id) / pinned
  * endpoint   = per-request observed host URL variants
  * envelope   = BLOCK2 fixed order [activity_kind, client_sdk, 10, 5.0.0]

Oracle: rec[46:78] == sha256_iv2(frame || claims), frame validated 9/9 on the
Android gold vectors (see _sub_ios_claims2_oracle.py).
"""
import itertools
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from _sub_ios_claims2_oracle import (
    load_corpus, oracle_batch, build_claims, block2, ADJ_SIGNING_ID,
)

OUT = {}

corpus = load_corpus()
by_kind = {}
for r in corpus:
    by_kind.setdefault(r["kind"], []).append(r)
for k, v in sorted(by_kind.items()):
    print("kind %-12s n=%2d  params=%s" % (k, len(v), sorted(len(x["val"]) for x in v)[:5]))

sess = [r for r in corpus if r["kind"] == "session"][0]
print("session record:", sess["file"], sess["host"])

# ----------------------------------------------------------------------
# key inventory for the session record
# ----------------------------------------------------------------------
SESSION_WIRE = sorted(sess["val"])
print("session wire keys (%d):" % len(SESSION_WIRE))
for k in SESSION_WIRE:
    print("   %-28s = %r" % (k, sess["val"][k][:60]))

# Android-law analogs present on the iOS session wire
ANDROID_SESSION_PROFILE = ["app_token", "app_version", "created_at", "device_name",
                           "device_type", "environment", "installed_at", "os_name",
                           "os_version"]
ANDROID_SESSION_TAIL = ["session_count"]

ENDPOINT_VALS = [
    "https://consent.adjust.io",     # observed host of 0144
    "https://consent.adjust.com",    # the other choice array entry
    "consent.adjust.io",
    "https://consent.adjust.io/session",
    None,                            # absent (endpoint not claimed)
]

def candidates_session(membership_mask, endpoint, tail_keys, pinned):
    """membership_mask: frozenset of wire keys claimed in the profile."""
    val = dict(sess["val"])
    if endpoint is not None:
        val["endpoint"] = endpoint
    return build_claims(val, membership_mask, tail_keys, "session", pinned=pinned)

# ----------------------------------------------------------------------
# Stage A — explicit, structured laws (no toggle blow-up)
# ----------------------------------------------------------------------
stage_a = []
law_names = []

full = frozenset(SESSION_WIRE)                      # every wire key claimed
for ep in ENDPOINT_VALS:
    for tail in ([], ["session_count"], ["started_at"], ["session_count", "started_at"]):
        for pinned in (ADJ_SIGNING_ID, None):
            for pinned_first in ((False,) if pinned else (False,)):
                stage_a.append((full, ep, tail, pinned))
                law_names.append("full ep=%r tail=%r pinned=%r first=%r"
                                 % (ep, tail, pinned, pinned_first))

# Android-analog with endpoint
for ep in ENDPOINT_VALS:
    pool = frozenset(ANDROID_SESSION_PROFILE)
    stage_a.append((pool, ep, ["session_count"], ADJ_SIGNING_ID))
    law_names.append("android-analog ep=%r" % ep)

claims_list = []
for full_mask, ep, tail, pinned in stage_a:
    claims_list.append(candidates_session(full_mask, ep, tail, pinned))

singles = [(c, name) for c, name in zip(claims_list, law_names)]
hits = []
# evaluate in one batch per frame (single frame here)
import numpy as np
res = oracle_batch(sess, [c for c, _ in singles])
for (c, name), ok in zip(singles, res):
    if ok:
        hits.append((name, c))
print("Stage A: %d laws -> %d hits" % (len(singles), len(hits)))
OUT["stage_a"] = {"n_laws": len(singles), "hits": [h[0] for h in hits]}

# ----------------------------------------------------------------------
# Stage B — membership toggles over the iOS-specific keys
# ----------------------------------------------------------------------
TOGGLE_KEYS = [k for k in SESSION_WIRE if k not in
               ("app_token", "app_version", "created_at", "device_name",
                "device_type", "environment", "os_name", "os_version")]
print("Stage B toggle keys (%d):" % len(TOGGLE_KEYS), TOGGLE_KEYS)

BASE_PROFILE = [k for k in ("app_token", "app_version", "created_at",
                            "device_name", "device_type", "environment",
                            "installed_at", "os_name", "os_version")
                if k in sess["val"]]

TAIL_CHOICES = [(), ("session_count",), ("started_at",),
                ("session_count", "started_at")]
PINNED_CHOICES = [ADJ_SIGNING_ID, None]

def stage_b(endpoint_list, max_report=5):
    hits = []
    total = 0
    for ep in endpoint_list:
        val = dict(sess["val"])
        if ep is not None:
            val["endpoint"] = ep
        for tail in TAIL_CHOICES:
            for pinned in PINNED_CHOICES:
                batch = []
                masks = []
                for bits in itertools.product([0, 1], repeat=len(TOGGLE_KEYS)):
                    prof = list(BASE_PROFILE)
                    for k, b in zip(TOGGLE_KEYS, bits):
                        if b:
                            prof.append(k)
                    batch.append(build_claims(val, prof, list(tail), "session",
                                              pinned=pinned))
                    masks.append(bits)
                total += len(batch)
                res = oracle_batch(sess, batch)
                for bits, c, ok in zip(masks, batch, res):
                    if ok:
                        hits.append({"endpoint": ep, "tail": list(tail),
                                     "pinned": pinned, "mask": bits,
                                     "claims": c.decode("latin1")})
    return hits, total

hits_b, total_b = stage_b(ENDPOINT_VALS)
print("Stage B: %d candidates -> %d hits" % (total_b, len(hits_b)))
OUT["stage_b"] = {"n": total_b, "hits": hits_b}

with open(os.path.join(HERE, "_sub_ios_claims2_out.json"), "w") as f:
    json.dump(OUT, f, indent=1)
print("wrote _sub_ios_claims2_out.json")
