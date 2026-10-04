"""_d8solve.py — GF(2) column solve for descriptor #8 (and #9) against the
CLEAN golden s1 signature.

Model: body words 0..3 = F(bit0(d0[0..2]), bit0(d4[4]), d8[16B], d9[20B],
d2, d5, d6, d7, d10, second).  Hold everything at the corpus values except
d8; build one column per d8 bit by flipping it, then solve for the delta that
reaches the golden target.  Solvable with delta==0 => d8 constant is right.
Solvable with delta!=0 => we recover the golden's d8.  Unsolvable => d8 is
NOT the golden's problem (something else is).
"""
import base64, json, os, re, struct, sys, time
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mint_pipeline as M

A = json.load(open(os.path.join(HERE, "all_signings.json")))
G = json.load(open(os.path.join(HERE, "golden_saz.json")))
ROW = 4
SEC = {"s1": 1788856523, "s2": 1788856523, "s3": 1788856526, "s4": 1788856528}
ZW = int(os.environ.get("ADJ9_ZW", "4"))

_STATE = {}


def corpus_base(r):
    return {bi: bytes.fromhex(r.get("d%d" % bi, "")) for bi in M.VA_ORDER}


def golden_claims(tag, kind):
    c = dict(G[tag]["params"])
    c.update(M.INTERNAL_CLAIMS)
    c["activity_kind"] = kind
    return c


def descs_for(base, tag, kind, over=None):
    d0 = base[0]
    d4 = base[4]
    dd, _m = M.build_descriptors(golden_claims(tag, kind), kind, d0,
                                 base[2], d4)
    # dd is in VA_ORDER; rebuild dict by index
    by = {i: dd[k] for k, i in enumerate(M.VA_ORDER)}
    by[0] = (len(d0) // 4, 0, d0)
    by[4] = (len(d4) // 4, 0, d4)
    if over:
        for i, b in over.items():
            by[i] = (len(b) // 4, 0, b)
    return [by[i] for i in M.VA_ORDER]


def mint_w(descs, second):
    blob, info = M.finex_mint(descs, second, max_steps=60_000_600)
    return list(struct.unpack(">48I", blob))[4:4 + ZW]


def _job(a):
    (tag, kind, over_hex) = a
    over = {int(k): bytes.fromhex(v) for k, v in over_hex.items()}
    base = _STATE["base"]
    t = time.time()
    w = mint_w(descs_for(base, tag, kind, over), SEC[tag])
    return (a, w, time.time() - t)


def solve(c, cols, target):
    """GF(2): find x (one word per column) with c ^ XOR cols[i]*x[i] == target."""
    n = len(cols)
    eqs = []
    for j in range(ZW):
        for b in range(32):
            mask = 0
            for i in range(n):
                if (cols[i][j] >> b) & 1:
                    mask |= 1 << (i * 32 + b)
            if mask:
                eqs.append((mask, ((target[j] ^ c[j]) >> b) & 1))
    piv = {}
    for mask, bit in eqs:
        v, bb = mask, bit & 1
        while v:
            q = v.bit_length() - 1
            if q in piv:
                pm, pb = piv[q]
                v ^= pm
                bb ^= pb
            else:
                piv[q] = (v, bb)
                break
        else:
            if bb:
                return None, len(piv), len(eqs)
    sol = 0
    for q in sorted(piv):
        v, bb = piv[q]
        rest = v & ~(1 << q)
        if bb ^ (bin(rest & sol).count("1") & 1):
            sol |= 1 << q
    return sol, len(piv), len(eqs)


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "s1"
    kind = sys.argv[2] if len(sys.argv) > 2 else "session"
    which = sys.argv[3] if len(sys.argv) > 3 else "8"
    base = corpus_base(A[ROW])
    _STATE["base"] = base
    b = base64.b64decode(re.search(r'signature="([^"]+)"',
                                   G[tag]["auth"]).group(1))
    target = list(struct.unpack(">44I", b[16:]))[:ZW]
    print("target", ["%08x" % w for w in target], flush=True)

    c = mint_w(descs_for(base, tag, kind), SEC[tag])
    print("base    ", ["%08x" % w for w in c], flush=True)
    print("delta   ", ["%08x" % (target[j] ^ c[j]) for j in range(ZW)],
          flush=True)

    which = int(which)
    nbits = len(base[which]) * 8
    jobs = []
    for k in range(nbits):
        bb = bytearray(base[which])
        bb[k // 8] ^= 1 << (k % 8)
        jobs.append((tag, kind, {str(which): bytes(bb).hex()}))
    t0 = time.time()
    with Pool(13) as p:
        res = p.map(_job, jobs, chunksize=1)
    cols = [r[1] for r in res]
    # linearity self-check
    bb = bytearray(base[which])
    bb[0] ^= 1
    chk = mint_w(descs_for(base, tag, kind, {which: bytes(bb)}), SEC[tag])
    lin = all((c[j] ^ cols[0][j]) == chk[j] for j in range(ZW))
    print("linearity(self-check bit0): %s  %s" %
          (lin, "" if lin else ("base^col=%s actual=%s" %
                                (["%08x" % (c[j] ^ cols[0][j]) for j in range(ZW)],
                                 ["%08x" % chk[j] for j in range(ZW)]))),
          flush=True)
    sol, rank, neq = solve(c, cols, target)
    print("ncols=%d neq=%d rank=%d  SOLVED=%s" % (len(cols), neq, rank,
                                                  sol is not None), flush=True)
    if sol is not None:
        dbytes = bytearray(base[which])
        words = ["%08x" % ((sol >> (n * 32)) & 0xFFFFFFFF)
                 for n in range(len(cols) // 32)]
        print("sol words (per 32 bits):", " ".join(words))
        for n in range(len(cols) // 32):
            v = (sol >> (n * 32)) & 0xFFFFFFFF
            if v:
                dbytes[4 * n:4 * n + 4] = struct.pack(">I", v)
        print("required #%s = %s (delta only; full value shown)" %
              (which, bytes(dbytes).hex()))
    print("elapsed %.1f s" % (time.time() - t0))


if __name__ == "__main__":
    main()
