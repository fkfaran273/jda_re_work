"""DEFINITIVE: is each golden 44-word body inside the GF(2)-affine image of
the descriptor inputs, and WHICH input set is needed?

Model (verified linear on the corpus): body = body0 XOR (XOR of columns),
columns sampled by flipping one bit at a time at a fixed base point.

Membership test: target XOR body0 must lie in span{columns}.
Equivalently rank(columns U {target^body0}) == rank(columns).
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

# input sets: name -> list of (bi, byte_off, nbits)
def words(bi, w0, n):
    return [(bi, 4 * (w0 + i)) for i in range(n)]

SETS = {
    "region": ([(0, 4 * w) for w in range(4)] +
               [(4, 4 * w) for w in (4, 5, 6)] + [(2, 0)]),
    "#8": [(8, b) for b in range(16)],
    "#9": [(9, b) for b in range(20)],
    "#7": [(7, 0)],
    "#5": [(5, 0)],
    "#6": [(6, 0)],
    "#4full": [(4, b) for b in range(0, 32, 8)],
    "#0full": [(0, b) for b in range(0, 144, 24)],
    "#10": [(10, b) for b in range(0, 360, 24)],
}


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
    key, bi, off, bit, dmap, second = a
    d = {k: v for k, v in dmap.items() if k != "_base"}
    v = bytearray(d[bi])
    v[off] ^= 1 << bit
    d[bi] = bytes(v)
    body, err = mint_body(d, second)
    if body is None:
        return (key, bi, off, bit, None)
    base = dmap["_base"]
    return (key, bi, off, bit, body)


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


def pack(bits, body, base):
    v = 0
    for j in range(44):
        v |= (body[j] ^ base[j]) << (j * 32)
    return v


def main():
    tag = sys.argv[1]
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
    D = pack([], target, base)
    print("%s  base ok  target ok  D=%d bits" % (tag, D.bit_length()),
          flush=True)

    jobs = []
    for key, locs in SETS.items():
        for bi, off in locs:
            for bit in range(8):
                jobs.append((key, bi, off, bit, dmap, second))
    print("jobs:", len(jobs), flush=True)
    cols = []
    with ProcessPoolExecutor(max_workers=16) as ex:
        for r in ex.map(job, jobs, chunksize=1):
            cols.append(r)
    print("done, nones:", sum(1 for c in cols if c[4] is None), flush=True)
    json.dump([[c[0], c[1], c[2], c[3], c[4]] for c in cols],
              open(os.path.join(HERE, "_g8_full_%s.json" % tag), "w"))

    by = {}
    for key, bi, off, bit, body in cols:
        if body is None:
            continue
        by.setdefault(key, []).append(pack([], body, base))

    order = ["region", "#8", "#9", "#7", "#5", "#6"]
    acc = []
    for k in order:
        acc += by.get(k, [])
        r0 = rank(acc)
        r1 = rank(acc + [D])
        print("cumulative %-22s ncols=%-5d rank=%-5d rank+D=%-5d  D_IN_SPAN=%s"
              % ("+".join(order[:order.index(k) + 1]), len(acc), r0, r1,
                 r1 == r0), flush=True)
    # standalone
    for k in order:
        v = by.get(k, [])
        print("standalone %-20s ncols=%-5d rank=%-4d rank+D=%-4d D_IN_SPAN=%s"
              % (k, len(v), rank(v), rank(v + [D]), rank(v + [D]) == rank(v)),
              flush=True)


if __name__ == "__main__":
    main()
