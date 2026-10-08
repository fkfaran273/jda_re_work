# -*- coding: utf-8 -*-
"""freeze_vectors.py -- extract the 6 verified iOS signature vectors from the
capture into frozen_vectors.json for adj7_ios_pure.py's selftest.

kind = the activity_kind value proven by the claims-law match:
    third_party_sharing -> third_party_sharing
    sdk_click           -> click
    session             -> session
    attribution         -> attribution
"""
import json
import os
import re
import sys
import zipfile
from calendar import timegm
from datetime import datetime
from urllib.parse import parse_qsl, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from probe2_claims import (cbc_decrypt, key_schedule,  # noqa
                           parse_record, CIPHER_RE)
from probe3_header import parse_iso_offset  # noqa

SEED = bytes.fromhex(
    "f110fb41676dba311f38c652c8f951ec"
    "3db456c07b9166a509bef66cd870654b")

KIND_MAP = {
    "third_party_sharing": "third_party_sharing",
    "sdk_click": "click",
    "session": "session",
    "attribution": "attribution",
}


def main():
    jf = os.path.join(HERE, "nirio_08Sep",
                      "nirioiosauto_08Sep_ios_CT_adjust.json")
    recs = json.load(open(jf, encoding="utf-8"))
    RK = key_schedule(SEED)
    out = []
    for r in recs:
        auth = next((v for k, v in r["request_headers"]
                     if k.lower() == "authorization"), "")
        client_sdk = next((v for k, v in r["request_headers"]
                           if k.lower() == "client-sdk"), "")
        sig = CIPHER_RE.search(auth).group(1)
        blob = bytes.fromhex(sig)
        rec = cbc_decrypt(blob[16:272], blob[:16], RK)
        p = parse_record(rec)
        assert p, f"sid {r['sid']}: record parse failed"
        if isinstance(r["body"], dict):
            params = dict(r["body"])
        else:
            params = dict(parse_qsl(urlsplit(r["url"]).query,
                                    keep_blank_values=True))
        path = urlsplit(r["url"]).path.rsplit("/", 1)[-1]
        kind = KIND_MAP[path]
        out.append({
            "sid": r["sid"],
            "endpoint": path,
            "kind": kind,
            "client_sdk": client_sdk,
            "native_version": "3.61.0",
            "headers_id": "7",
            "params": params,
            "second": None,
            "nonce12": p["nonce12"].hex(),
            "sig": sig,
        })
    # signing second: probe3 brute-forced the header seed per request.  For
    # sids 32/33/39 it equals created_at's second, but 36/37/38 were queued
    # and signed 1-4 s later (signing = send moment, NOT created_at).
    BRUTE_SECONDS = {"32": 1788846069, "33": 1788846069,
                     "36": 1788846070, "37": 1788846071,
                     "38": 1788846073, "39": 1788846076}
    for v in out:
        v["second"] = BRUTE_SECONDS[v["sid"]]
        created = v["params"].get("created_at")
        if created:
            m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", created)
            base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
            v["created_at_sec"] = (timegm(base.timetuple())
                                   - 5 * 3600 - 30 * 60)
    assert all(v["second"] for v in out), "every vector needs a second"
    path_out = os.path.join(HERE, "frozen_vectors.json")
    with open(path_out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    print(f"froze {len(out)} vectors -> {path_out}")
    for v in out:
        print(f"  sid {v['sid']} {v['kind']:20s} sec={v['second']} "
              f"nonce={v['nonce12']} sig={v['sig'][:16]}..")


if __name__ == "__main__":
    main()
