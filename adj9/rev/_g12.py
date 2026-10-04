"""Measure the exact GF(2) region->body map at a GOLDEN (second, kind) and
solve the golden body against it.

body = c XOR L(region),  region = 8 words (d0[0..3], d4[4..6], d2[0]) = 256 bits.
1408 output bits >> 256 inputs, so solve() is a genuine overdetermined
CONSISTENCY TEST: if it solves, the golden body is fully explained by the
region alone (with whatever non-region descriptors were used as the base).
"""
import base64, json, os, re, struct, sys
from concurrent.futures import ProcessPoolExecutor
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mint_pipeline as M
import bodymodel as BM
from _z8lib import mint_body

A = json.load(open(os.path.join(HERE, "all_signings.json")))
G = json.load(open(os.path.join(HERE, "golden_saz.json")))
ZW144, Z, ZW32 = bytes(144), bytes(4), bytes(32)
SEC = {"s1": 1788856523, "s2": 1788856523, "s3": 1788856526, "s4": 1788856528}
KIND = {"s1": "session", "s2": "click", "s3": "sdk_info", "s4": "attribution"}
NVAR = BM.NVAR
NAMES = [a[0] for a in BM.ACTIVE]


def golden_body(tag):
    b = base64.b64decode(re.search(r'signature="([^"]+)"',
                                   G[tag]["auth"]).group(1))
    return list(struct.unpack(">44I", b[16:])), b.hex()


def base_dmap(tag):
    r = A[4]
    d = {bi: bytes.fromhex(r.get("d%d" % bi, "")) for bi in M.VA_ORDER}
    claims = dict(G[tag]["params"])
    claims.update(M.INTERNAL_CLAIMS)
    claims["activity_kind"] = KIND[tag]
    dd, _m = M.build_descriptors(claims, KIND[tag], ZW144, Z, ZW32)
    d[10] = dd[6][2]
    d[7] = dd[5][2]
    return d


def set_words(d, words):
    """words: {name: u32} patch into d0/d2/d4."""
    d = dict(d)
    for n, (name, bi, w) in enumerate(BM.ACTIVE):
        pass
    return d


def patch_region(d, vec):
    """vec: 256-bit int, bit 32*n+b -> word n bit (31-b)."""
    d = dict(d)
    reg = {0: bytearray(d[0]), 2: bytearray(d[2]), 4: bytearray(d[4])}
    for n, (name, bi, w) in enumerate(BM.ACTIVE):
        val = (vec >> (32 * n)) & 0xFFFFFFFF
        reg[bi][4 * w:4 * w + 4] = struct.pack(">I", val)
    for bi in (0, 2, 4):
        d[bi] = bytes(reg[bi])
    return d


def job(a):
    d, second, vec = a
    body, err = mint_body(d, second)
    return None if body is None else body


def main():
    tag = sys.argv[1]
    second = SEC[tag]
    d0map = base_dmap(tag)
    cache = os.path.join(HERE, "_g12_%s.json" % tag)
    vecs = BM.draw_samples(NVAR, 12345)
    if os.path.exists(cache):
        raw = json.load(open(cache))
        if raw.get("vecs") == vecs:
            print("cache hit", cache, flush=True)
            m = BM.Model.from_raw(raw, KIND[tag])
            return report(tag, m, second, d0map)
    zero = {0: ZW144, 2: Z, 4: ZW32}
    dbase = dict(d0map)
    dbase.update(zero)
    jobs = [(dbase, second, None)] + [(dbase, second, v) for v in vecs]
    # extra held-out samples to VALIDATE affinity (not used to fit)
    hold = [(dbase, second, BM.draw_samples(1, 999 + k)[0]) for k in range(4)]
    with ProcessPoolExecutor(max_workers=16) as ex:
        res = list(ex.map(job, jobs))
        res2 = list(ex.map(job, hold))
    if res[0] is None or any(r is None for r in res):
        print("MINT FAILED", tag)
        return
    raw = {"key": "g12-%s" % tag, "second": second, "kind": KIND[tag],
           "nsamp": NVAR, "vecs": vecs, "c": res[0], "bodies": res[1:]}
    json.dump(raw, open(cache, "w"))
    m = BM.Model.from_raw(raw, KIND[tag])
    print("model rank", m.rank, flush=True)
    # affinity validation on held-out regions
    for (dd, sec, v), got in zip(hold, res2):
        words = {NAMES[n]: (v >> (32 * n)) & 0xFFFFFFFF
                 for n in range(len(NAMES))}
        pred = m.predict(words)
        print("  heldout affine predict match:", pred == got,
              " words", {k: "%08x" % v2 for k, v2 in words.items()}, flush=True)
    return report(tag, m, second, d0map)


def report(tag, m, second, d0map):
    body, hexb = golden_body(tag)
    sol = m.solve(body)
    print("GOLDEN", tag, "solve:", "CONSISTENT" if sol else "INCONSISTENT",
          flush=True)
    if sol:
        r = sol.pop("_rank")
        print("  solve_rank", r)
        for k, v in sol.items():
            print("   %-4s %08x" % (k, v))
        print("  body_predict_match", m.predict(sol) == body)
        d = patch_region(d0map, 0)
        words = dict(sol)
        reg = {0: bytearray(ZW144), 2: bytearray(Z), 4: bytearray(ZW32)}
        for n, (name, bi, w) in enumerate(BM.ACTIVE):
            reg[bi][4 * w:4 * w + 4] = struct.pack(">I", words[name])
        dd = dict(d0map)
        for bi in (0, 2, 4):
            dd[bi] = bytes(reg[bi])
        rb, err = mint_body(dd, second)
        print("  REMINT byte-exact:", rb == body, flush=True)
        if rb is not None and rb != body:
            print("  remint diff words:",
                  [j for j in range(44) if rb[j] != body[j]])
    else:
        # how far off?  solve the least-squares-ish: report rank of cols
        print("  (no solution)")
    return sol


if __name__ == "__main__":
    main()
