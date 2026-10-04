"""sweep2_one.py <cand_hex8> — FinEx with descs[4] (#2) overridden, score F0 window."""
import json, struct, sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
D = json.load(open(os.path.join(HERE, "fin_descs.json")))
SEED = D["target"]["second"]
TGT = bytes.fromhex(D["target"]["blob_hex"])
TGT_DW = [struct.unpack_from(">I", TGT, 4 * i)[0] for i in range(48)]
S0 = 0x5500000000
cand = sys.argv[1].lower()
descs = []
for i, d in enumerate(D["descs"]):
    hx = cand if i == 4 else d["data_hex"]
    descs.append((d["len_dw"], 0, bytes.fromhex(hx) if hx else b""))
ex = FinEx(SEED, descs)
status = ex.run(max_steps=20_000_000)
out = {}
for (s, n, v) in ex.emit_trace:
    out[(s, n)] = v
got = [out.get((S0, k), 0) for k in range(48)]
score = sum(1 for k in range(48) if got[k] == TGT_DW[k])
print("cand=%s status=%s score=%d/48" % (cand, status, score), flush=True)
