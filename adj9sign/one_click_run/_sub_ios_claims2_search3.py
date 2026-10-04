"""_sub_ios_claims2_search3.py — Stage D: the frame x membership cross product.

Neither earlier stage covered {full membership over ALL wire keys} x
{alternative BLOCK tail frames}.  In particular:

  * frame A  ... || 02 || "iPhone13,2"+pad   (record-sourced, prior law)
  * frame B  ... || 01 || 00*16              (the shared Android constant)
  * frame C  ... || 02 || 00*16
  * frame D  ... || 01 || device_field

and the iOS record itself carries device_name in the descriptor-7 field, so
the claims may EXCLUDE device_name (toggled here, it was hard-wired in Stage
C's base profile).

Session record 0144; membership over all 26 wire keys (session_count fixed to
the tail per the Android law, started_at toggled), adj_verification in 3
forms, pinned after-profile or absent.
"""
import itertools
import json
import os
import struct
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from _sub_ios_claims2_oracle import load_corpus, ADJ_SIGNING_ID
import adj9_signer as sg
import _sub_np_sha256 as npsha
import _sub_ios_mint as m

OUT = json.load(open(os.path.join(HERE, "_sub_ios_claims2_out.json")))

corpus = load_corpus()
sess = [r for r in corpus if r["kind"] == "session"][0]
val0 = dict(sess["val"])

ADJ_V_FORMS = [("none", None),
               ("b64-sim", "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"),
               ("b64-ios", m.make_adj_verification("ios"))]

TAILS = [("session_count",), ("session_count", "started_at"), (), ("started_at",)]
PINNEDS = [ADJ_SIGNING_ID, None]
DEV_IN_PROFILE = [True, False]          # device_name toggled
FRAMES = [
    ("02+dev", b"\x02", sess["dev"]),
    ("01+00*16", b"\x01", b"\x00" * 16),
    ("02+00*16", b"\x02", b"\x00" * 16),
    ("01+dev", b"\x01", sess["dev"]),
]

# oracle with parameterised frame
SHA0 = __import__("hashlib").sha256(b"").digest()


def oracle_frame(rec, claims_list, frame_tag, frame_var, frame_dev):
    d9 = b"\x00" * 20
    head = (d9 + b"\x00\x08" + rec["head16"] + struct.pack("<I", rec["S"]) + SHA0)
    pref, rest0 = head[:64], head[64:]
    target = np.frombuffer(rec["block"], ">u4").astype(np.uint32)
    L0 = 74 + 17
    rows = []
    for c in claims_list:
        c = c.encode("latin1") if isinstance(c, str) else c
        total = L0 + len(c)
        tail = rest0 + frame_var + frame_dev + c
        tail = tail + b"\x80" + b"\x00" * ((55 - total) % 64) \
            + struct.pack(">Q", total * 8)
        rows.append(np.frombuffer(tail, np.uint8))
    T = max(len(r) for r in rows)
    if T % 64:
        T += 64 - T % 64
    rests = np.zeros((len(rows), T), dtype=np.uint8)
    for i, r in enumerate(rows):
        rests[i, :len(r)] = r
    words = npsha.batch_digests(pref, rests)
    return (words == target).all(axis=1)


BASE = [k for k in ("app_token", "app_version", "created_at", "device_type",
                    "environment", "installed_at", "os_name", "os_version")
        if k in val0]
TOGGLES = sorted(k for k in val0 if k not in BASE
                 and k != "session_count")
print("base (%d): %s" % (len(BASE), BASE))
print("toggles (%d): %s" % (len(TOGGLES), TOGGLES))

hits = []
total = 0
chunk = 65536
for frame_tag, fvar, fdev in FRAMES:
    for tail in TAILS:
        for pinned in PINNEDS:
            for dev_in in DEV_IN_PROFILE:
                for adjv_name, adjv in ADJ_V_FORMS:
                    val = dict(val0)
                    if adjv is not None:
                        val["adj_verification"] = adjv
                    prof_fixed = list(BASE) + (["device_name"] if dev_in else [])
                    if adjv is not None:
                        prof_fixed = prof_fixed + ["adj_verification"]
                    prof_fixed = [k for k in prof_fixed if k not in tail]
                    for lo in range(0, 1 << len(TOGGLES), chunk):
                        hi = min(lo + chunk, 1 << len(TOGGLES))
                        batch = []
                        for bits in range(lo, hi):
                            prof = list(prof_fixed)
                            for i, k in enumerate(TOGGLES):
                                if (bits >> i) & 1:
                                    prof.append(k)
                            parts = []
                            for k in sorted(prof):
                                v = val.get(k)
                                if v:
                                    parts.append(v)
                            if pinned:
                                parts.append(pinned)
                            for k in sorted(tail):
                                parts.append(val[k])
                            parts.append("session" + "ios5.8.0" + "10" + "5.0.0")
                            batch.append("".join(parts))
                        res = oracle_frame(sess, batch, frame_tag, fvar, fdev)
                        total += len(batch)
                        for j, ok in enumerate(res):
                            if ok:
                                bits = lo + j
                                mask = [k for i, k in enumerate(TOGGLES)
                                        if (bits >> i) & 1]
                                hits.append({"frame": frame_tag, "tail": list(tail),
                                             "pinned": pinned, "dev_in": dev_in,
                                             "adj_verification": adjv_name,
                                             "mask": mask,
                                             "claims": batch[j]})
                    # end chunk loop
print("Stage D: %d candidates -> %d hits" % (total, len(hits)))
OUT["stage_d"] = {"n": total, "hits": hits}
with open(os.path.join(HERE, "_sub_ios_claims2_out.json"), "w") as f:
    json.dump(OUT, f, indent=1)
print("wrote _sub_ios_claims2_out.json")
