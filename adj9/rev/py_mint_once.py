# py_mint_once.py - mint ONE attribution-law blob for the genuine payload and save
# its bytes, so the region bisection (py_region.py) has a "wrong" blob to splice
# against the genuine one.
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import adj9_forge as F

FILL = {"adj_signing_id": "1500000", "activity_kind": "attribution",
        "client_sdk": "android5.7.0", "headers_id": "10",
        "native_version": "5.0.0",
        "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"}

G = json.load(open(os.path.join(HERE, "fresh_genuine.json"), encoding="utf-8"))
val = {}
import urllib.parse
for k, v in urllib.parse.parse_qs(G["query"].split("?", 1)[1],
                                  keep_blank_values=True).items():
    val[k] = v[0]
val_att = dict(FILL)
val_att.update(val)
second = 1789474915
t0 = time.time()
st, blob, desc, unp = F.make_signature_law(val_att, "attribution", second=second)
gen = bytes.fromhex(G["blob_hex"])
diff = [i for i in range(48) if blob[i * 4:i * 4 + 4] != gen[i * 4:i * 4 + 4]]
print("status=%s #10=%dB unpadded=%d  %.1fs" % (st, len(desc), unp, time.time() - t0))
print("diff dwords: %d/48" % len(diff))
json.dump({"blob_hex": blob.hex(), "genuine_hex": gen.hex(), "second": second,
           "desc10_len": len(desc), "unpadded": unp, "diff": diff},
          open(os.path.join(HERE, "py_mint_once.json"), "w"), indent=1)
print("saved py_mint_once.json")