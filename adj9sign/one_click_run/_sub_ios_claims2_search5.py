"""_sub_ios_claims2_search5.py — Stage F: the simulator-rewrite hypothesis.

The capture is an ios-simulator build: the Authorization header carries
adj_verification = f("ios-simulator") while the wire body says os_name=ios.
The native lib therefore KNOWS it runs on a simulator and rewrites the
platform string.  If the lib also rewrites the os_name CLAIM value to
"ios-simulator", every earlier candidate (built with os_name="ios") was
wrong by 6 bytes.

Space: os_name value in {ios, ios-simulator} x full membership over the other
wire keys x adj_verification {none, b64-sim, b64-ios} x tail x pinned x
2 frames.  Session record 0144.
"""
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

OSNAMES = ["ios", "ios-simulator"]
ADJV_VALS = [("none", None),
             ("b64-sim", "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"),
             ("b64-ios", "KlcAG2cbAAsKSl1KXiwSSjA=")]
TAILS = [("session_count",), (), ("session_count", "started_at"), ("started_at",)]
PINNEDS = [ADJ_SIGNING_ID, None]
FRAMES = [("02+dev", b"\x02", sess["dev"]), ("01+00*16", b"\x01", b"\x00" * 16)]

TOGGLES = sorted(k for k in val0 if k not in ("session_count", "os_name"))
print("toggles (%d): %s" % (len(TOGGLES), TOGGLES))

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
        tail = rest0 + fvar + fdev + c
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
for frame_tag, fvar, fdev in FRAMES:
  for osname in OSNAMES:
    for adjv_name, adjv in ADJV_VALS:
      for tail in TAILS:
        for pinned in PINNEDS:
            val = dict(val0)
            val["os_name"] = osname
            if adjv is not None:
                val["adj_verification"] = adjv
            fixed = [k for k in ("app_token", "app_version", "created_at",
                                 "device_name", "device_type", "environment",
                                 "installed_at", "os_name", "os_version")
                     if k in val]
            if adjv is not None:
                fixed.append("adj_verification")
            fixed = [k for k in fixed if k not in tail]
            for lo in range(0, 1 << len(TOGGLES), chunk):
                hi = min(lo + chunk, 1 << len(TOGGLES))
                batch = []
                for bits in range(lo, hi):
                    prof = list(fixed)
                    for i, k in enumerate(TOGGLES):
                        if (bits >> i) & 1:
                            prof.append(k)
                    pool = {k: val[k] for k in prof}
                    parts = [pool[k] for k in sorted(pool)]
                    if pinned:
                        parts.append(pinned)
                    for k in sorted(tail):
                        parts.append(val[k])
                    parts.append("session" + "ios5.8.0" + "10" + "5.0.0")
                    batch.append("".join(parts))
                res = oracle(batch)
                total += len(batch)
                for j, ok in enumerate(res):
                    if ok:
                        bits = lo + j
                        mask = [k for i, k in enumerate(TOGGLES)
                                if (bits >> i) & 1]
                        hits.append({"frame": frame_tag, "os_name": osname,
                                     "adj_verification": adjv_name,
                                     "tail": list(tail), "pinned": pinned,
                                     "mask": mask, "claims": batch[j]})
        print("  cumulative %d hits %d" % (total, len(hits)))
print("Stage F: %d candidates -> %d hits" % (total, len(hits)))
OUT["stage_f"] = {"n": total, "hits": hits}
with open(os.path.join(HERE, "_sub_ios_claims2_out.json"), "w") as f:
    json.dump(OUT, f, indent=1)
print("wrote out.json")
