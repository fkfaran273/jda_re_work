"""hflip_test.py — closest feasible to 'random H': single-bit flip. Does it even terminate?"""
import base64, datetime, json, struct, sys, time, urllib.parse, urllib.request, uuid, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header
D = json.load(open(os.path.join(HERE, "fin_descs.json")))
ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
by0 = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"])) for d in D["descs"]}
H_REAL = by0[4][1]
print("real H:", H_REAL.hex()[:32], "...")
for flip in ("1bit", "random"):
    h = bytearray(H_REAL)
    if flip == "1bit":
        h[0] ^= 1
    else:
        import secrets; h = bytearray(secrets.token_bytes(32))
    by = dict(by0); by[4] = (8, bytes(h)); by[0] = (36, bytes(144))
    sec = int(time.time()) + 35
    ex = FinEx(sec, [(by[i][0], 0, by[i][1]) for i in ORDER])
    t0 = time.time()
    status = ex.run(max_steps=20_000_000)
    print(f"H={flip}: status={status} steps={ex.steps} nrand={ex.nrand} ({time.time()-t0:.0f}s)", flush=True)
print("done")
