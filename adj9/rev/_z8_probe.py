"""Which descriptor bits reach body words 0..3 (the 'region-only zone')?

Uses the golden s1 descriptor set (corpus #8/#9 + golden #10) and flips a
single bit per descriptor byte to measure the GF(2) column of the body.
"""
import json, os, sys
from concurrent.futures import ProcessPoolExecutor
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mint_pipeline as M
from _z8lib import mint_body

A = json.load(open(os.path.join(HERE, "all_signings.json")))
G = json.load(open(os.path.join(HERE, "golden_saz.json")))
ZW144, Z, ZW32 = bytes(144), bytes(4), bytes(32)
SEC = {"s1": 1788856523, "s2": 1788856523, "s3": 1788856526, "s4": 1788856528}


def corpus_base():
    r = A[4]
    return {bi: bytes.fromhex(r.get("d%d" % bi, "")) for bi in M.VA_ORDER}


def golden_descs(tag, gbase):
    claims = dict(G[tag]["params"])
    claims.update(M.INTERNAL_CLAIMS)
    claims["activity_kind"] = "session"
    dd, _m = M.build_descriptors(claims, "session", ZW144, Z, ZW32)
    d = dict(gbase)
    d[10] = dd[6][2]
    d[7] = dd[5][2]
    return {bi: d[bi] for bi in M.VA_ORDER}


def job(a):
    tag, bi, off, bit, dmap, second = a
    d = dict(dmap)
    v = bytearray(d[bi])
    v[off] ^= 1 << bit
    d[bi] = bytes(v)
    body, err = mint_body(d, second)
    return (bi, off, bit, None if body is None else
            [i for i in range(44) if body[i] != d["_base"][i]], err)


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "s1"
    nbytes = int(sys.argv[2]) if len(sys.argv) > 2 else 64
    second = SEC[tag]
    dmap = golden_descs(tag, corpus_base())
    base, err = mint_body(dmap, second)
    if base is None:
        print("BASE MINT FAILED", err)
        return
    dmap["_base"] = base
    print(tag, "base body[0:6]", ["%08x" % w for w in base[:6]], flush=True)

    jobs = []
    for bi in M.VA_ORDER:
        n = len(dmap[bi])
        for off in range(min(n, nbytes)):
            jobs.append((tag, bi, off, 0, dmap, second))
    res, fails = {}, []
    with ProcessPoolExecutor(max_workers=16) as ex:
        for bi, off, bit, diff, err in ex.map(job, jobs, chunksize=1):
            if diff is None:
                fails.append((bi, off, err))
            elif diff:
                res.setdefault(bi, []).append((off, bit, diff))
    for bi in M.VA_ORDER:
        n = len(dmap[bi])
        hits = res.get(bi, [])
        nf = len([f for f in fails if f[0] == bi])
        if hits:
            allw = sorted({w for x in hits for w in x[2]})
            z3 = [x for x in hits if max(x[2]) < 8]
            print("desc#%-2d len=%-4d  hits=%-3d zone03=%-3d fail=%-3d "
                  "words=%s" % (bi, n, len(hits), len(z3), nf, allw[:14]),
                  flush=True)
        else:
            print("desc#%-2d len=%-4d  NO effect  fail=%d" % (bi, n, nf),
                  flush=True)


if __name__ == "__main__":
    main()
