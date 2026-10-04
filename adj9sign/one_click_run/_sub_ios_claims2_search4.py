"""_sub_ios_claims2_search4.py — Stage E: the remaining untested cells.

Pool = 26 wire keys + endpoint + adj_verification TOGETHER (Stage B had only
endpoint, Stage C/D only adj_verification), x envelope mode:
    block2-last    : sorted(pool) + pinned + BLOCK2        (Android law)
    sorted-no-env  : sorted(pool incl. activity_kind/client_sdk) + pinned
    pinned-first   : pinned + sorted(pool) + BLOCK2
x endpoint value x adj_verification value.
Tail: session_count after pinned (Android law); toggles over the other wire
keys.  Session record 0144, standard frame (02 || dev).
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
import _sub_np_sha256 as npsha

OUT = json.load(open(os.path.join(HERE, "_sub_ios_claims2_out.json")))

corpus = load_corpus()
sess = [r for r in corpus if r["kind"] == "session"][0]
val0 = dict(sess["val"])
SHA0 = __import__("hashlib").sha256(b"").digest()

EP_VALS = [("none", None),
           ("io", "https://consent.adjust.io"),
           ("com", "https://consent.adjust.com")]
ADJV_VALS = [("none", None),
             ("b64-sim", "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"),
             ("b64-ios", "KlcAG2cbAAsKSl1KXiwSSjA=")]
MODES = ["block2-last", "sorted-no-env", "pinned-first"]

TOGGLES = sorted(k for k in val0 if k != "session_count")
print("toggles (%d)" % len(TOGGLES))

d9 = b"\x00" * 20
head = d9 + b"\x00\x08" + sess["head16"] + struct.pack("<I", sess["S"]) + SHA0
pref, rest0 = head[:64], head[64:]
target = np.frombuffer(sess["block"], ">u4").astype(np.uint32)


def oracle(claims_list):
    L0 = 74 + 17
    rows = []
    for c in claims_list:
        c = c.encode("latin1") if isinstance(c, str) else c
        total = L0 + len(c)
        tail = rest0 + b"\x02" + sess["dev"] + c
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


hits = []
total = 0
chunk = 65536
for mode in MODES:
    for ep_name, ep in EP_VALS:
        for adjv_name, adjv in ADJV_VALS:
            extras = []
            if ep is not None:
                extras.append(("endpoint", ep))
            if adjv is not None:
                extras.append(("adj_verification", adjv))
            for lo in range(0, 1 << len(TOGGLES), chunk):
                hi = min(lo + chunk, 1 << len(TOGGLES))
                batch = []
                for bits in range(lo, hi):
                    prof = [k for i, k in enumerate(TOGGLES) if (bits >> i) & 1]
                    prof.append("session_count")
                    parts = []
                    if mode == "pinned-first":
                        parts.append(ADJ_SIGNING_ID)
                    if mode == "sorted-no-env":
                        prof = prof + ["activity_kind", "client_sdk"]
                    pool = {k: val0[k] for k in prof}
                    for k, v in extras:
                        pool[k] = v
                    parts.extend(pool[k] for k in sorted(pool))
                    if mode != "pinned-first":
                        parts.append(ADJ_SIGNING_ID)
                    if mode != "sorted-no-env":
                        parts.append("session" + "ios5.8.0" + "10" + "5.0.0")
                    batch.append("".join(parts))
                res = oracle(batch)
                total += len(batch)
                for j, ok in enumerate(res):
                    if ok:
                        bits = lo + j
                        mask = [k for i, k in enumerate(TOGGLES)
                                if (bits >> i) & 1]
                        hits.append({"mode": mode, "endpoint": ep_name,
                                     "adj_verification": adjv_name,
                                     "mask": mask, "claims": batch[j]})
print("Stage E: %d candidates -> %d hits" % (total, len(hits)))
OUT["stage_e"] = {"n": total, "hits": hits}
with open(os.path.join(HERE, "_sub_ios_claims2_out.json"), "w") as f:
    json.dump(OUT, f, indent=1)
print("wrote out.json")
