"""chainchar2.py — full affine characterization of the adj9 serializer.

Every descriptor word of a corpus row is treated as one input variable.  For
each, a FinEx run with ONLY that word set to 1 (all other region words zero,
non-region descriptors kept) yields the body's response column.  With the
zero-region constant c this gives an exact GF(2) model

    body[0..43] = c  XOR  SUM_inputs  col[input] & value(input)

which inverts the adj9 wire whitening without re-running the VM.
"""
import sys, os, json, time, struct
from concurrent.futures import ProcessPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mint_pipeline as M

ROW = int(os.environ.get("CHAIN_ROW", "7"))
SECOND = int(os.environ.get("CHAIN_SECOND", "0")) or None
REGION = ("d0", "d4", "d2")            # zeroed for every unit run


def inputs():
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    r = asg[ROW]
    out = []
    for name in ("d0", "d2", "d4", "d5", "d6", "d7", "d8", "d9", "d10"):
        hx = r.get(name, "")
        n = len(bytes.fromhex(hx)) // 4 if hx else 0
        for w in range(n):
            out.append((name, w))
    return out, len(bytes.fromhex(asg[ROW]["d10"])) // 4


INS, _ = inputs()


def descriptors(override):
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    r, p = asg[ROW], ph3[ROW]
    d = {}
    for name in ("d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10"):
        hx = r.get(name, "")
        d[name] = bytearray(bytes.fromhex(hx)) if hx else bytearray()
    for name, w in override.items():
        buf = bytearray(len(d[name]))
        if 4 * w < len(buf):
            buf[4 * w] = 1
        d[name][:] = bytes(buf)
    descs = []
    for bi in M.VA_ORDER:
        data = bytes(d["d%d" % bi])
        descs.append((len(data) // 4, 0, data))
    return descs, int(p["second"])


def one(job):
    ci, second = job
    ov = {name: 0 for name in REGION}
    if ci is not None:
        name, w = INS[ci]
        ov = dict(ov)
        ov[name] = w
    descs, sec = descriptors(ov)
    sec = second if second is not None else sec
    blob, info = M.finex_mint(descs, sec, max_steps=60_000_000)
    return ci, list(struct.unpack(">48I", blob)), info["status"]


if __name__ == "__main__":
    second = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1] != "-" else None
    jobs = [(None, second)] + [(i, second) for i in range(len(INS))]
    t0 = time.time()
    res = {}
    with ProcessPoolExecutor(max_workers=14) as pool:
        for ci, words, st in pool.map(one, jobs):
            res["c" if ci is None else str(ci)] = words
    tag = ("row%d" % ROW) if second is None else ("s%d" % second)
    json.dump({"row": ROW, "second": second, "inputs": INS, "res": res},
              open(os.path.join(HERE, "af_%s.json" % tag), "w"))
    print("WROTE af_%s.json  %d runs  %.0fs" % (tag, len(jobs), time.time() - t0))
