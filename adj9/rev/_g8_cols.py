"""GF(2) column basis over region(8 words) + #8(16 B) + #9(20 B).

Answers: is each golden's 44-word body in the span of these inputs?
Uses only the SINK stream, all 44 body words as equations.
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


# variable -> (bi, byte offset, nbits)
REG = [("d0w%d" % w, 0, 4 * w) for w in range(4)] + \
      [("d4w%d" % w, 4, 4 * w) for w in (4, 5, 6)] + \
      [("d2w0", 2, 0)]
VARS = REG + [("d8b%d" % b, 8, b) for b in range(16)] + \
       [("d9b%d" % b, 9, b) for b in range(20)]


def job(a):
    tag, name, bi, off, bit, dmap, second = a
    d = dict(dmap)
    d.pop("_base", None)
    v = bytearray(d[bi])
    v[off] ^= 1 << bit
    d[bi] = bytes(v)
    body, err = mint_body(d, second)
    if body is None:
        return (name, bit, None)
    base = dmap["_base"]
    return (name, bit, body)


def gf2rank(vs):
    piv = {}
    for v in vs:
        while v:
            q = v.bit_length() - 1
            if q in piv:
                v ^= piv[q]
            else:
                piv[q] = v
                break
    return len(piv)


def solve_consistent(target, cols, names):
    """cols: list of (name, bit, body44).  Returns (consistent, rank)."""
    eqs = []
    for name, bit, body in cols:
        if body is None:
            continue
        col = 0
        for j in range(44):
            w = body[j] ^ target[j]
            col |= w << (j * 32)
        if col:
            eqs.append(col)
    piv = {}
    bad = False
    for v in eqs:
        cur = v
        while cur:
            q = cur.bit_length() - 1
            if q in piv:
                cur ^= piv[q]
            else:
                piv[q] = cur
                break
        else:
            bad = True
            break
    return (not bad), len(piv)


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "s1"
    second = SEC[tag]
    dmap = golden_descs(tag, corpus_base())
    base, err = mint_body(dmap, second)
    if base is None:
        print("BASE FAILED", err)
        return
    dmap["_base"] = base
    import base64, re, struct
    b = base64.b64decode(re.search(r'signature="([^"]+)"',
                                  G[tag]["auth"]).group(1))
    target = list(struct.unpack(">44I", b[16:]))
    print(tag, "base ok, target ok", flush=True)

    jobs = []
    for name, bi, off in VARS:
        for bit in range(8):
            jobs.append((tag, name, bi, off, bit, dmap, second))
    cols = []
    with ProcessPoolExecutor(max_workers=16) as ex:
        for r in ex.map(job, jobs, chunksize=1):
            cols.append(r)
    json.dump([[n, bt, bb] for n, bt, bb in cols],
              open(os.path.join(HERE, "_g8_cols_%s.json" % tag), "w"))
    print("columns built:", len(cols),
          "nones:", sum(1 for _n, _b, x in cols if x is None), flush=True)

    # per-variable column sets
    def sel(pred):
        return [c for c in cols if c[2] is not None and pred(c[0])]

    sets = {
        "region only": sel(lambda n: n.startswith(("d0w", "d4w", "d2w"))),
        "region + #8": sel(lambda n: n.startswith(("d0w", "d4w", "d2w", "d8"))),
        "region + #9": sel(lambda n: n.startswith(("d0w", "d4w", "d2w", "d9"))),
        "region + #8 + #9": sel(lambda n: not n.startswith("_")),
    }
    for k, v in sets.items():
        ok, rk = solve_consistent(target, v, None)
        print("%-20s ncols=%-4d rank=%-4d CONSISTENT=%s"
              % (k, len(v), rk, ok), flush=True)


if __name__ == "__main__":
    main()
