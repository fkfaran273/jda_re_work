"""chainchar.py — determine the adj9 body whitening as an exact GF(2) map.

Body (44 dwords, blob words 4..47) is an AFFINE function over GF(2) of the
45 "plaintext" words  P = (d0[0..35] || d4[0..7] || d2).

    body = c(known inputs)  XOR  SUM_i  col_i & P_i

Columns are obtained by re-running the FinEx VM once per unit plaintext word;
the constant c by re-running with the whole region zeroed.  Parallel workers.
"""
import sys, os, json, struct, time
from concurrent.futures import ProcessPoolExecutor
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mint_pipeline as M

ROW = int(os.environ.get("CHAIN_ROW", "7"))
SECOND = int(os.environ.get("CHAIN_SECOND", "0")) or None
COLS = json.loads(os.environ.get("CHAIN_COLS", "[]"))

# plaintext unit list: (desc, word index)
PLAIN = [("d0", i) for i in range(36)] + [("d4", i) for i in range(8)] + [("d2", 0)]
NPLAIN = len(PLAIN)


def descriptors(region_override=None):
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    r, p = asg[ROW], ph3[ROW]
    d = {}
    for bi in M.VA_ORDER:
        hx = r.get("d%d" % bi, "")
        d["d%d" % bi] = bytearray(bytes.fromhex(hx)) if hx else bytearray()
    if region_override is not None:
        for bi in ("d0", "d4", "d2"):
            d[bi][:] = bytes(region_override.get(bi, b"").ljust(len(d[bi]), b"\x00"))
    descs = []
    for bi in M.VA_ORDER:
        data = bytes(d["d%d" % bi])
        descs.append((len(data) // 4, 0, data))
    return descs, int(p["second"])


def one(job):
    ci, second = job
    ov = {}
    if ci is None:                       # constant: whole region zeroed
        ov = {b: b"\x00" * n for b, n in (("d0", 144), ("d4", 32), ("d2", 4))}
    else:
        dname, wi = PLAIN[ci]
        n = {"d0": 144, "d4": 32, "d2": 4}[dname]
        buf = bytearray(n)
        buf[4 * wi] = 1                  # bit0 of the word (BE -> high byte)
        ov = {dname: bytes(buf)}
    descs, sec = descriptors(ov)
    sec = second if second is not None else sec
    blob, info = M.finex_mint(descs, sec, max_steps=60_000_000)
    return ci, list(struct.unpack(">48I", blob)), info["status"]


if __name__ == "__main__":
    second = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1] != "-" else None
    jobs = [(None, second)] + [(i, second) for i in range(NPLAIN)]
    t0 = time.time()
    res = {}
    with ProcessPoolExecutor(max_workers=12) as pool:
        for ci, words, st in pool.map(one, jobs):
            res["c" if ci is None else str(ci)] = words
            print("done col %s  %.0fs  %s" % (ci, time.time() - t0, st), flush=True)
    out = {"row": ROW, "second": second or descriptors()[1], "nplain": NPLAIN,
           "plain": PLAIN, "res": res}
    json.dump(out, open(os.path.join(HERE, "chainchar_%s.json" % (
        "row%d" % ROW if second is None else "s%d" % second)), "w"))
    print("WROTE chainchar_%s.json  total %.0fs" % (
        "row%d" % ROW if second is None else "s%d" % second, time.time() - t0))
