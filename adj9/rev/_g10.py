"""Decisive: is the golden body reachable when #8 and #9 are FREE?

Full bit basis over: region(256) + #8(128) + #9(160) + #7(32) + #5(32) + #6(32)
= 640 columns.  Then solve for the implied #8 / #9 if consistent.
"""
import base64, json, os, re, struct, sys
from concurrent.futures import ProcessPoolExecutor
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mint_pipeline as M
from _z8lib import mint_body

A = json.load(open(os.path.join(HERE, "all_signings.json")))
G = json.load(open(os.path.join(HERE, "golden_saz.json")))
ZW144, Z, ZW32 = bytes(144), bytes(4), bytes(32)
SEC = {"s1": 1788856523, "s2": 1788856523, "s3": 1788856526, "s4": 1788856528}
KIND = {"s1": "session", "s2": "click", "s3": "sdk_info", "s4": "attribution"}


def corpus_base():
    r = A[4]
    return {bi: bytes.fromhex(r.get("d%d" % bi, "")) for bi in M.VA_ORDER}


def golden_descs(tag, gbase):
    claims = dict(G[tag]["params"])
    claims.update(M.INTERNAL_CLAIMS)
    claims["activity_kind"] = KIND[tag]
    dd, _m = M.build_descriptors(claims, KIND[tag], ZW144, Z, ZW32)
    d = dict(gbase)
    d[10] = dd[6][2]
    d[7] = dd[5][2]
    return {bi: d[bi] for bi in M.VA_ORDER}


def job(a):
    name, bi, off, bit, dmap, second = a
    d = {k: v for k, v in dmap.items() if k != "_base"}
    v = bytearray(d[bi])
    v[off] ^= 1 << bit
    d[bi] = bytes(v)
    body, err = mint_body(d, second)
    if body is None:
        return (name, None)
    return (name, [b ^ x for b, x in zip(body, dmap["_base"])])


def rank(vs):
    piv = {}
    for v in vs:
        cur = v
        while cur:
            q = cur.bit_length() - 1
            if q in piv:
                cur ^= piv[q]
            else:
                piv[q] = cur
                break
    return len(piv)


def packv(delta):
    v = 0
    for j in range(44):
        v |= delta[j] << (j * 32)
    return v


def main():
    tag = sys.argv[1]
    extra_d10 = len(sys.argv) > 2 and sys.argv[2] == "d10"
    second = SEC[tag]
    dmap = golden_descs(tag, corpus_base())
    base, err = mint_body(dmap, second)
    if base is None:
        print("BASE FAILED", err)
        return
    dmap["_base"] = base
    b = base64.b64decode(re.search(r'signature="([^"]+)"',
                                  G[tag]["auth"]).group(1))
    target = list(struct.unpack(">44I", b[16:]))
    D = packv([t ^ x for t, x in zip(target, base)])

    locs = {"region": ([(0, 4 * w + b) for w in range(4) for b in range(4)] +
                       [(4, 4 * w + b) for w in (4, 5, 6) for b in range(4)] +
                       [(2, 0)])}
    for k, n in ((8, 16), (9, 20), (7, 4), (5, 4), (6, 4)):
        locs["+d%d" % k] = [(k, b) for b in range(n)]
    if extra_d10:
        locs["+d10"] = [(10, b) for b in range(len(dmap[10]))]
    jobs = [(nm, bi, off, bit, dmap, second)
            for nm, ls in locs.items() for bi, off in ls
            for bit in range(8)]
    print(tag, "jobs", len(jobs), flush=True)
    by = {}
    with ProcessPoolExecutor(max_workers=16) as ex:
        for nm, dv in ex.map(job, jobs, chunksize=1):
            if dv is not None:
                by.setdefault(nm, []).append(packv(dv))
    acc = []
    for nm in locs:
        acc += by.get(nm, [])
        r0, r1 = rank(acc), rank(acc + [D])
        print("  %-18s ncols=%-5d rank=%-5d rank+D=%-5d D_IN_SPAN=%s"
              % (nm, len(acc), r0, r1, r0 == r1), flush=True)
    # standalone #8 / #9 membership (can #8 alone explain D, with region free?)
    reg = by.get("region", [])
    for extra in ("+d8", "+d9", "+d10"):
        if extra in by:
            v = reg + by[extra]
            r0, r1 = rank(v), rank(v + [D])
            print("  region%-6s + %-5s rank=%-5d rank+D=%-5d D_IN_SPAN=%s"
                  % ("", extra, r0, r1, r0 == r1), flush=True)


if __name__ == "__main__":
    main()
