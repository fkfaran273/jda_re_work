"""_finex_probe.py - FinEx descriptor-ablation probes: which descriptors does
the 48-dword wire output actually consume?  Usage: python _finex_probe.py NAME"""
import json, struct, sys, time
sys.path.insert(0, ".")
from fin_vm2 import FinEx
from collections import defaultdict

D = json.load(open("fin_descs.json"))
BASE = [(d["len_dw"], 0, bytes.fromhex(d["data_hex"])) for d in D["descs"]]
SEED = D["target"]["second"]
BLOB = bytes.fromhex(D["target"]["blob_hex"])
TGT = [struct.unpack_from(">I", BLOB, 4*i)[0] for i in range(48)]

def zdesc(descs, va):
    out = []
    for i, (l, t, data) in enumerate(descs):
        if i == va:
            out.append((l, t, b"\x00" * len(data)))
        else:
            out.append((l, t, data))
    return out

def sdesc(descs, va, newdata):
    l, t, data = descs[va]
    d2 = bytearray(data); d2[:len(newdata)] = newdata
    return [(l if i != va else l, t, bytes(d2) if i == va else dd) for i, (ll, tt, dd) in enumerate(descs)]

PROBES = {
    "baseline":  (BASE, SEED),
    "zero0":     (zdesc(BASE, 0), SEED),      # #0 region 144 B -> 0
    "zero2":     (zdesc(BASE, 4), SEED),      # va4 = #2 fine stamp
    "zero4":     (zdesc(BASE, 3), SEED),      # va3 = #4 region 32 B
    "zero9":     (zdesc(BASE, 1), SEED),      # va1 = #9 cert-SHA1
    "zero10":    (zdesc(BASE, 6), SEED),      # va6 = #10 claims record
    "zero8":     (zdesc(BASE, 2), SEED),      # va2 = #8 anchor flags
    "zero7":     (zdesc(BASE, 5), SEED),      # va5 = #7 claims len
    "seed+1":    (BASE, SEED + 1),            # rand stream shifted (header too)
    "seed+8":    (BASE, SEED + 8),            # rand stream shifted by 8 draws
}

def run(name, descs, seed):
    t0 = time.time()
    ex = FinEx(seed, descs)
    st = ex.run(max_steps=60_000_000)
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = defaultdict(dict)
    for ((sva, n), v) in last.items():
        bys[sva][n] = v
    best, bs = -1, None
    for sva, m in bys.items():
        c = sum(1 for j, v in enumerate(TGT) if m.get(j) == v)
        if c > best: best, bs = c, sva
    m = bys[bs]
    hh = sum(1 for j in range(4) if m.get(j) == TGT[j])
    bb = sum(1 for j in range(4, 48) if m.get(j) == TGT[j])
    # which words changed vs baseline target = TGT (device blob)
    diffw = [j for j in range(48) if m.get(j) != TGT[j]]
    print("PROBE %-9s status=%-10s steps=%8d %.0fs nrand=%d match=%2d/48 (hdr %d/4 body %d/44) sink=0x%x" % (
        name, st, ex.steps, time.time()-t0, ex.nrand, best, hh, bb, bs))
    print("   diff words vs captured blob (%d): %s" % (len(diffw), diffw[:60]))
    return m, diffw

if __name__ == "__main__":
    name = sys.argv[1]
    descs, seed = PROBES[name]
    run(name, descs, seed)
