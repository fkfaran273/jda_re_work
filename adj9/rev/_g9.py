"""Full-basis span membership for the goldens, with structural variants.

MODE:
  region256  -- all 256 bits of the 8 region words
  plus:<k>   -- additionally all bits of descriptor k
"""
import base64, json, os, re, struct, sys
from concurrent.futures import ProcessPoolExecutor
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mint_pipeline as M
from _z8lib import mint_body

A = json.load(open(os.path.join(HERE, "all_signings.json")))
G = json.load(open(os.path.join(HERE, "golden_saz.json")))
P = json.load(open(os.path.join(HERE, "pair_h3.json")))
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
    key, bi, off, bit, dmap, second = a
    d = {k: v for k, v in dmap.items() if k != "_base"}
    v = bytearray(d[bi])
    v[off] ^= 1 << bit
    d[bi] = bytes(v)
    body, err = mint_body(d, second)
    return (key, bi, off, bit, None if body is None else
            [b ^ x for b, x in zip(body, dmap["_base"])])


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


def run(tag, sets, second=None, dmap=None, target=None, label=""):
    second = second or SEC[tag]
    if dmap is None:
        dmap = golden_descs(tag, corpus_base())
    base, err = mint_body(dmap, second)
    if base is None:
        print("BASE FAILED", err)
        return None
    dmap["_base"] = base
    if target is None:
        b = base64.b64decode(re.search(r'signature="([^"]+)"',
                                      G[tag]["auth"]).group(1))
        target = list(struct.unpack(">44I", b[16:]))
    D = packv([t ^ x for t, x in zip(target, base)])

    jobs = []
    for key, locs in sets.items():
        for bi, off in locs:
            for bit in range(8):
                jobs.append((key, bi, off, bit, dmap, second))
    by = {}
    with ProcessPoolExecutor(max_workers=16) as ex:
        for key, bi, off, bit, dv in ex.map(job, jobs, chunksize=1):
            if dv is not None:
                by.setdefault(key, []).append(packv(dv))
    acc = []
    for k in sets:
        acc += by.get(k, [])
        r0, r1 = rank(acc), rank(acc + [D])
        print("  %-30s ncols=%-5d rank=%-5d rank+D=%-5d D_IN_SPAN=%s"
              % (k, len(acc), r0, r1, r0 == r1), flush=True)
    return (by, base, target, D)


REG = {}


def reg_set():
    s = []
    for w in range(4):
        for b in range(4):
            s.append((0, 4 * w + b))
    for w in (4, 5, 6):
        for b in range(4):
            s.append((4, 4 * w + b))
    s.append((2, 0))
    return s


def main():
    what = sys.argv[1]
    if what == "corpus":
        # sanity: does the pipeline reproduce a corpus blob byte-exactly?
        r = A[4]
        d = {bi: bytes.fromhex(r.get("d%d" % bi, "")) for bi in M.VA_ORDER}
        blob, info = M.finex_mint([(len(d[bi]) // 4, 0, d[bi])
                                   for bi in M.VA_ORDER], int(P[4]["second"]),
                                  max_steps=60_000_600)
        print("corpus row4 byte-exact:", bytes(blob) ==
              bytes.fromhex(P[4]["blob"]), flush=True)
        w1 = list(struct.unpack(">48I", blob))
        w2 = list(struct.unpack(">48I", bytes.fromhex(P[4]["blob"])))
        print("  word mismatches:", sum(1 for a, b in zip(w1, w2) if a != b))
        return
    if what == "region":
        tag = sys.argv[2]
        run(tag, {"region256": reg_set()})
        return
    if what == "plus":
        # region256 + all bits of one descriptor
        tag = sys.argv[2]
        bi = int(sys.argv[3])
        sets = {"region256": reg_set(),
                "+d%d" % bi: [(bi, b) for b in range(len(
                    golden_descs(tag, corpus_base())[bi]))]}
        run(tag, sets)
        return
    if what == "d10":
        tag = sys.argv[2]
        n = len(golden_descs(tag, corpus_base())[10])
        run(tag, {"region256": reg_set(),
                  "+d10": [(10, b) for b in range(n)]})
        return


if __name__ == "__main__":
    main()
