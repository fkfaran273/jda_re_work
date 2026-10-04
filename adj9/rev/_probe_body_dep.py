import json, struct, sys, time
sys.path.insert(0, ".")
from fin_vm2 import FinEx
from collections import defaultdict

VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
asg = json.load(open("all_signings.json"))
ph3 = json.load(open("pair_h3.json"))

def descs_of(r):
    out = []
    for bi in VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytes.fromhex(hx) if hx else b""
        out.append((len(data)//4, 0, data))
    return out

def f0(descs, seed, steps=60_000_000):
    ex = FinEx(seed, descs)
    st = ex.run(max_steps=steps)
    by = {}
    for (sva, n, v) in ex.emit_trace:
        if (sva & 0xFFFFFFFFFFFF) == 0x5500000000:
            by[n & 0xFFFFFFFF] = v & 0xFFFFFFFF
    return [by.get(i) for i in range(48)], st, ex.nrand

i = int(sys.argv[1]) if len(sys.argv) > 1 else 0
r, p = asg[i], ph3[i]
tgt = [struct.unpack_from(">I", bytes.fromhex(p["blob"]), 4*j)[0] for j in range(48)]
seed = p["second"]

variants = {
  "orig": descs_of(r),
}
# zero the region plane (d0,d2,d4) and also d7/d10
import copy
d = [list(x) for x in descs_of(r)]
d[0] = (d[0][0], 0, b"\x00"*(d[0][0]*4))     # #0 zero
d[4] = (d[4][0], 0, b"\x00"*(d[4][0]*4))     # #2 zero
d[3] = (d[3][0], 0, b"\x00"*(d[3][0]*4))     # #4 zero
variants["region_zeroed"] = [tuple(x) for x in d]
d2v = [list(x) for x in descs_of(r)]
d2v[5] = (1, 0, b"\x00\x00\x00\x00")          # #7 = 0
d2v[6] = (len(d2v[6][2])//4, 0, b"\x00"*(len(d2v[6][2])))  # #10 zeros
variants["claims_zeroed"] = [tuple(x) for x in d2v]

for name, dd in variants.items():
    t0 = time.time()
    o, st, nr = f0(dd, seed)
    m = sum(1 for k in range(48) if o[k] == tgt[k])
    print("%-14s status=%s nrand=%d match=%d/48  %.0fs" % (name, st, nr, m, time.time()-t0), flush=True)
    if name == "region_zeroed":
        print("   body match:", sum(1 for k in range(4,48) if o[k]==tgt[k]), "/44")
        print("   words:", " ".join("%08x"%x for x in o[4:10]))
        print("   tgt  :", " ".join("%08x"%x for x in tgt[4:10]))
