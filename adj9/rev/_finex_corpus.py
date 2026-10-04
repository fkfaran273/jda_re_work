"""_finex_corpus.py - python-only body reproduction on corpus rows:
FinEx(second, descs from all_signings.json) vs pair_h3.json blob."""
import json, struct, sys, time
sys.path.insert(0, ".")
from fin_vm2 import FinEx
from collections import defaultdict

VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
asg = json.load(open("all_signings.json"))
ph3 = json.load(open("pair_h3.json"))
rows = [int(x) for x in sys.argv[1].split(",")] if len(sys.argv) > 1 else [0, 1, 4, 5, 6, 7]

for i in rows:
    r, p = asg[i], ph3[i]
    descs = []
    for bi in VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytes.fromhex(hx) if hx else b""
        lendl = len(data) // 4
        descs.append((lendl, 0, data[:lendl * 4]))
    seed = p["second"]
    blob = bytes.fromhex(p["blob"])
    tgt = [struct.unpack_from(">I", blob, 4 * j)[0] for j in range(len(blob) // 4)]
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
        c = sum(1 for j, v in enumerate(tgt) if m.get(j) == v)
        if c > best:
            best, bs = c, sva
    m = bys[bs]
    hh = sum(1 for j in range(4) if m.get(j) == tgt[j])
    bb = sum(1 for j in range(4, len(tgt)) if m.get(j) == tgt[j])
    diffw = [j for j in range(len(tgt)) if m.get(j) != tgt[j]]
    print("ROW %d second=%d status=%s steps=%d %.0fs nrand=%d match=%d/%d (hdr %d/4 body %d/%d) sink=0x%x" % (
        i, seed, st, ex.steps, time.time() - t0, ex.nrand, best, len(tgt), hh, bb, len(tgt) - 4, bs))
    print("   diff words (%d): %s" % (len(diffw), diffw[:50]))
    for j in diffw[:8]:
        print("      w%-2d cap=%08x finex=%s" % (j, tgt[j], "%08x" % m.get(j, 0)))
    sys.stdout.flush()
