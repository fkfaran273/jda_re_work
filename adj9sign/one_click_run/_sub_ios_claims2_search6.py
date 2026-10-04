"""_sub_ios_claims2_search6.py — Stage F/G: the combined final candidate space.

Pool (server-derivable values only, per the open SDK source + sibling report
_sub_sdk_source_RESULT.md):
    26 wire keys (os_name optionally rewritten to "ios-simulator")
    + adj_verification  {absent, f("ios-simulator"), f("ios")}
    + endpoint          {absent, https://consent.adjust.io, .com, +path}
    + algorithm         {absent, "adj9"}          (iOS exceptionKey)
envelope: sorted(pool) + pinned "1500000" + sorted tail + BLOCK2, over
tail/pinned variants and 2 BLOCK-tail frames.
Session record 0144.
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

ADJV = [("none", None),
        ("sim", "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"),
        ("ios", "KlcAG2cbAAsKSl1KXiwSSjA=")]
EP = [("none", None),
      ("io", "https://consent.adjust.io"),
      ("com", "https://consent.adjust.com"),
      ("io-path", "https://consent.adjust.io/session")]
ALG = [("none", None), ("adj9", "adj9")]
OSN = ["ios", "ios-simulator"]

BASE = ["app_token", "app_version", "created_at", "device_name",
        "device_type", "environment", "installed_at", "os_name", "os_version"]
TOGGLES = sorted(k for k in val0 if k not in BASE
                 and k not in ("session_count",))
TAILS = [("session_count",), ()]
PINNEDS = [ADJ_SIGNING_ID]
FRAMES = [("02+dev", b"\x02", sess["dev"]), ("01+00*16", b"\x01", b"\x00" * 16)]

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
  for osn in OSN:
    for tail in TAILS:
      for pinned in PINNEDS:
        for a_name, a_val in ADJV:
          for e_name, e_val in EP:
            for g_name, g_val in ALG:
                val = dict(val0)
                val["os_name"] = osn
                if a_val: val["adj_verification"] = a_val
                if e_val: val["endpoint"] = e_val
                if g_val: val["algorithm"] = g_val
                fixed = [k for k in BASE if k in val]
                for nm, vv in (("adj_verification", a_val),
                               ("endpoint", e_val), ("algorithm", g_val)):
                    if vv:
                        fixed.append(nm)
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
                            hits.append({"frame": frame_tag, "os_name": osn,
                                         "adj_verification": a_name,
                                         "endpoint": e_name, "algorithm": g_name,
                                         "tail": list(tail), "mask": mask,
                                         "claims": batch[j]})
  print("frame %s cumulative %d hits %d" % (frame_tag, total, len(hits)))
print("Stage F/G: %d candidates -> %d hits" % (total, len(hits)))
OUT["stage_fg"] = {"n": total, "hits": hits}
with open(os.path.join(HERE, "_sub_ios_claims2_out.json"), "w") as f:
    json.dump(OUT, f, indent=1)
print("wrote out.json")
