"""body_map.py - which body words depend on which descriptor word.
Differential FinEx on the DEVICE descriptors (signing A): flip one source
dword at a time, record which of the 44 body words flip."""
import json, sys, struct, random
sys.path.insert(0, ".")
from fin_vm2 import FinEx

D = json.load(open("fin_descs.json"))
tb = bytes.fromhex(D["target"]["blob_hex"])
TGT = [struct.unpack_from(">I", tb, 4 * i)[0] for i in range(48)]
BASE_DESCS = [(d["len_dw"], 0, bytes.fromhex(d["data_hex"])) for d in D["descs"]]
BI = {d["build_idx"]: k for k, d in enumerate(D["descs"])}

def f0(descs, maxsteps=20_000_000):
    ex = FinEx(D["target"]["second"], descs)
    ex.run(max_steps=maxsteps)
    by = {}
    for (sva, n, v) in ex.emit_trace:
        if (sva & 0xFFFFFFFFFFFF) == 0x5500000000:
            by[n] = v
    return [by.get(i) for i in range(48)]

base_out = f0(BASE_DESCS)
assert base_out[:4] == TGT[:4]
print("control ok, body diff baseline")
FLIPS = [(0, 0, "W0"), (0, 1, "X"), (0, 2, "T0"), (0, 5, "T3"),
         (2, 0, "d2"), (4, 0, "d4[0]"), (4, 6, "d4[6]"),
         (7, 0, "d7"), (8, 0, "d8[0]"), (9, 0, "d9[0]"), (10, 0, "claims[0]"),
         (10, 89, "claims[89]")]
out = {}
for bi, wi, name in FLIPS:
    descs = [list(d) for d in BASE_DESCS]
    k = BI[bi]
    data = bytearray(descs[k][2])
    if 4 * wi + 4 > len(data):
        data += b"\x00" * (4 * wi + 4 - len(data))
    data[4 * wi] ^= 0xFF
    descs[k][2] = bytes(data)
    o = f0([tuple(d) for d in descs])
    flips = [i - 4 for i in range(48) if o[i] != base_out[i] and i >= 4]
    out[name] = flips
    print("%-10s (build#%d word %d) -> %d body words flip: %s" % (name, bi, wi, len(flips), flips[:24]))
json.dump(out, open("fill_runs/body_map.json", "w"), indent=1)
