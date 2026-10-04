"""_sub_claims3_mint_check.py — generalization + byte-exact mint on a hit.

Given a hit {law, opt, frame?}, rebuild the claims for ALL 30 records with
the same law, verify the BLOCK oracle 30/30, then mint the full 192-byte
blobs through _sub_ios_mint's proven pipeline and score byte-exactness.
Usage: python _sub_claims3_mint_check.py <out.json> [hit_index]
"""
import base64
import json
import os
import re
import sys
import zipfile

import numpy as np
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj9_signer as sg
import _sub_claims3_search as S1
from _sub_claims3_oracle_fixed import oracle_batch_fixed, _ios_msg_head
import _sub_ios_mint as mint

SAZ = S1.SAZ


def law_by_name(name):
    if name in S1.LAWS:
        return S1.LAWS[name]
    import _sub_claims3_search2 as S2
    if name in S2.LAWS5:
        return S2.LAWS5[name]
    raise KeyError(name)


def main():
    out_json = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(HERE, "_sub_claims3_out.json")
    idx = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    data = json.load(open(out_json))
    hits = data.get("hits") or []
    if not hits:
        print("no hits recorded")
        return
    h = hits[idx]
    print("generalizing hit:", json.dumps(h)[:400])
    opt = json.loads(h["opt"])
    fn = law_by_name(h["law"])
    corpus = S1.load_corpus()
    recs = {r["file"]: r for r in corpus}

    # rebuild claims for all 30 records, verify against capture blocks
    ok = 0
    blob_scores = {}
    for r in corpus:
        claims = fn(r, opt)
        arr = oracle_batch_fixed(r, [claims])
        ok += int(arr[0])
    print("BLOCK oracle on all 30 records with this law: %d/30" % ok)
    if ok != 30:
        return

    # full mint through the proven pipeline
    z = zipfile.ZipFile(SAZ)
    full = 0
    for r in corpus:
        claims = fn(r, opt)
        blob = r["blob"]
        header = blob[:16]
        dev = r["rec"][114:130].decode("latin1").rstrip("\x00")
        rec2 = mint.build_record_ios(r["S"], r["rec"][3:19], claims,
                                     device_name=dev)
        body2 = sg.whiten_forward(rec2, header)
        minted = header + body2 + sg.predict_digest(body2)
        same = sum(1 for a, b in zip(minted, blob) if a == b)
        blob_scores[r["file"]] = same
        full += int(same == 192)
    print("full-blob byte-exact mints: %d/30" % full)
    print("scores:", blob_scores)
    with open(os.path.join(HERE, "_sub_claims3_mint_check_out.json"),
              "w") as f:
        json.dump({"law": h["law"], "opt": h["opt"], "block_ok": ok,
                   "full_blobs": full, "scores": blob_scores}, f, indent=1)


if __name__ == "__main__":
    main()
