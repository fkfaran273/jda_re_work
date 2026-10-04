"""mk_synthetic.py — build a SELF-CONSISTENT paired_mint.json from the offline
signer itself, purely to validate diff_paired.py's plumbing (P0..P6 must all
pass when device output == offline output for identical inputs).

This proves the differ's capture schema, VA_ORDER packing, header law and
region comparisons are wired correctly.  It does NOT prove device equivalence;
that is what paired_mint.py + diff_paired.py do on a real capture.
"""
import importlib.util
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "signer"))
sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")

import adj9_signer as S                       # noqa: E402

spec = importlib.util.spec_from_file_location(
    "pm", os.path.join(HERE, "paired_mint.py"))
pm = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(pm)
except SystemExit:
    pass

t = pm.parse_control(pm.CONTROL)
task = t[0]                      # session: 43 keys, the proven task
kind, wire = task["kind"], task["map"]
sec = int(time.time())
seed = S.new_seed()
head = S.head_for_kind(kind)
val = S.claims_from_wire(wire, kind)
print("kind=%s keys=%d sec=%d seed=0x%08x head=%s"
      % (kind, len(wire), sec, seed, [hex(h) for h in head]), flush=True)

descs = S.build_descriptors(val, kind, seed=seed, head=head)
by = {d: descs[i] for i, d in enumerate(S.VA_ORDER)}
drow = {}
for did, (n, tag, data) in by.items():
    drow[str(did)] = {"w0": (n << 2), "lenDwords": n,
                      "length": len(data), "hex": data.hex()}
print("descriptors: %s" % {k: v["lenDwords"] for k, v in sorted(drow.items(),
                                                              key=lambda x: int(x[0]))},
      flush=True)

blob, info = S.mint_blob(val, kind, second=sec, seed=seed, head=head)
print("mint: %s" % json.dumps(info)[:200], flush=True)

out = {
    "ts": time.time(),
    "synthetic": True,
    "kind": kind,
    "sdk": task["sdk"],
    "map": [[k, v] for k, v in wire.items()],
    "blob_hex": blob.hex(),
    "paired_row": {
        "sign_id": 9, "second": sec, "S": seed,
        "head": [{"w1": h} for h in head],
        "d10_len": drow["10"]["length"],
        "d10_hex": drow["10"]["hex"],
        "desc": drow,
    },
    "mint": info,
}
p = os.path.join(HERE, "artifacts", "paired_mint_synthetic.json")
json.dump(out, open(p, "w", encoding="utf-8"), indent=1)
print("wrote %s (%d bytes), blob=%dB" % (p, os.path.getsize(p), len(blob)))
