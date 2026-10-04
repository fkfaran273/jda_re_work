"""_dump_vectors.py — freeze the gate's 9 genuine vectors into one JSON so the
one_click_run signer can self-test with NO external files (no LSPosed logs,
no capture dirs).  Run from pure_signer/."""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pure_sign as P  # noqa: E402

vecs = []


def add(second, blob, val, kind, d9, app):
    val = dict(val)
    dec = P.decode_blob(blob)
    phase = P.solve_head_phase(dec["S"], dec["head"])
    cb = P.build_claims(val, kind)
    vecs.append({
        "app": app,
        "kind": kind,
        "second": int(second),
        "S": dec["S"],
        "head": list(phase) if phase else [0x2B],
        "d9_hex": d9,
        "blob_hex": blob.hex(),
        "map": val,
        "claims_sha256": hashlib.sha256(cb).hexdigest(),
        "unpadded_len": len(cb),
    })


for second, blob, val, kind in P._mine_creditsea():
    add(second, blob, val, kind, P.D9_CREDITSEA, "creditsea")
for second, blob, val, kind in P._mine_penti_wins():
    add(second, blob, val, kind, P.D9_PENTI, "penti")

out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "_vectors_tmp.json")
json.dump(vecs, open(out, "w", encoding="utf-8"), indent=1, sort_keys=True)
print("%d vectors -> %s" % (len(vecs), out))
for v in vecs:
    print("  %-9s %-11s second=%d S=%08x head=%s claims=%dB"
          % (v["app"], v["kind"], v["second"], v["S"], v["head"],
             v["unpadded_len"]))
