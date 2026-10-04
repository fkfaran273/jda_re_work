"""_sub_ios_claims2_search7.py — Stage H: envelope/permutation cleanup cells.

Small exhaustive sweep over envelope layouts and pool variants with FULL
membership (every wire key claimed), on the session record:

  envelopes: canonical BLOCK2, +algorithm tail, pinned-inside-BLOCK2,
             client_sdk-first, no-envelope-no-pinned, pinned-at-very-end
  pools:     all 26 wire keys (+ adj_verification sim/ios, + endpoint io/com)
  os_name:   ios / ios-simulator
  frames:    02+dev, 01+00*16
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

d9 = b"\x00" * 20
head = d9 + b"\x00\x08" + sess["head16"] + struct.pack("<I", sess["S"]) + SHA0
pref, rest0 = head[:64], head[64:]
target = np.frombuffer(sess["block"], ">u4").astype(np.uint32)

ENVS = [
    ("canon", ["activity_kind", "client_sdk", "headers_id", "native_version"]),
    ("canon+alg", ["activity_kind", "client_sdk", "headers_id",
                   "native_version", "algorithm"]),
    ("pinned-in", ["activity_kind", "client_sdk", "adj_signing_id",
                   "headers_id", "native_version"]),
    ("sdk-first", ["client_sdk", "activity_kind", "headers_id",
                   "native_version"]),
    ("none", []),
    ("pinned-end", []),
]
EXTRA_VALS = {"adj_verification": [None, "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb",
                                  "KlcAG2cbAAsKSl1KXiwSSjA="],
              "endpoint": [None, "https://consent.adjust.io",
                           "https://consent.adjust.com"],
              "algorithm": [None, "adj9"]}
OSN = ["ios", "ios-simulator"]
FRAMES = [("02+dev", b"\x02", sess["dev"]), ("01+00*16", b"\x01", b"\x00" * 16)]

hits = []
tested = 0
for frame_tag, fvar, fdev in FRAMES:
    for osn in OSN:
        val = dict(val0)
        val["os_name"] = osn
        for av in EXTRA_VALS["adj_verification"]:
            for ev in EXTRA_VALS["endpoint"]:
                for gv in EXTRA_VALS["algorithm"]:
                    pool = {k: val[k] for k in val
                            if k not in ("session_count",)}
                    if av: pool["adj_verification"] = av
                    if ev: pool["endpoint"] = ev
                    if gv: pool["algorithm"] = gv
                    tail_v = val["session_count"]
                    for env_name, env in ENVS:
                        for pinned_pos in (["profile"] if env_name != "pinned-end"
                                           else ["end"]):
                            parts = [pool[k] for k in sorted(pool)]
                            if env_name == "canon" or env_name == "canon+alg":
                                parts.append(ADJ_SIGNING_ID)
                            elif env_name == "pinned-in":
                                pass
                            elif env_name == "pinned-end":
                                pass
                            if env_name == "pinned-in":
                                pass
                            # tail session_count after pinned (canon modes)
                            if env_name in ("canon", "canon+alg", "pinned-in"):
                                parts.append(tail_v)
                            # envelope
                            for k in env:
                                if k == "adj_signing_id":
                                    parts.append(ADJ_SIGNING_ID)
                                elif k == "activity_kind":
                                    parts.append("session")
                                elif k == "client_sdk":
                                    parts.append("ios5.8.0")
                                elif k == "headers_id":
                                    parts.append("10")
                                elif k == "native_version":
                                    parts.append("5.0.0")
                                elif k == "algorithm":
                                    parts.append("adj9")
                            if env_name == "pinned-end":
                                parts.append(ADJ_SIGNING_ID)
                            claims = "".join(parts)
                            total = 74 + 17 + len(claims)
                            tailb = (rest0 + fvar + fdev
                                     + claims.encode("latin1")
                                     + b"\x80" + b"\x00" * ((55 - total) % 64)
                                     + struct.pack(">Q", total * 8))
                            words = npsha.batch_digests(
                                pref, np.frombuffer(tailb, np.uint8)
                                .reshape(1, -1).copy())
                            tested += 1
                            if (words[0] == target).all():
                                hits.append({"frame": frame_tag, "os": osn,
                                             "av": av, "ev": ev, "gv": gv,
                                             "env": env_name,
                                             "claims": claims})
print("Stage H: %d candidates -> %d hits" % (tested, len(hits)))
for h in hits[:5]:
    print(json.dumps(h)[:300])
OUT["stage_h"] = {"n": tested, "hits": hits}
with open(os.path.join(HERE, "_sub_ios_claims2_out.json"), "w") as f:
    json.dump(OUT, f, indent=1)
print("wrote out.json")
