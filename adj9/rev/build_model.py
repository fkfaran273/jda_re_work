"""build_model.py — exact GF(2) bit-level model of region -> body.

Only 8 region words ever reach the wire (verified by single-word probing):
    d0[0], d0[1], d0[2], d0[3], d4[4], d4[5], d4[6], d2[0]
=> 256 unknown input bits -> 44*32 = 1408 output bits.

The map is GF(2)-affine (proved in aff2.py).  We recover the exact linear
map by sampling 256 full-rank random inputs plus the zero input:

    B_b = L_b . V      (B_b = 1408x256 body bits, V = 256x256 input matrix)
    =>  L_b = B_b . V^-1

and verify on fresh random vectors.

Writes model_row7.json:
    c       : 44 zero-region body words (the affine constant)
    cols    : 256 output-bit bitmasks, one per input bit
              (bit j of cols[32*n + b] = output bit j set by input bit b)
    active  : the 8 (region, word) names
"""
import json, os, random, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M
from concurrent.futures import ProcessPoolExecutor

ROW = 7
NSAMP = 256          # >= number of unknown bits
ACTIVE = ((0, 0), (0, 1), (0, 2), (0, 3), (4, 4), (4, 5), (4, 6), (2, 0))
NW = len(ACTIVE)
NB = NW * 32
NOB = 44 * 32
SEED = 20260926


def _run(patch):
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    r, p = asg[ROW], ph3[ROW]
    descs = []
    for bi in M.VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytearray(bytes.fromhex(hx)) if hx else bytearray()
        descs.append([len(data) // 4, 0, bytes(data)])
    for (bi, wi), val in patch.items():
        i = M.VA_ORDER.index(bi)
        d = bytearray(descs[i][2])
        d[4 * wi:4 * wi + 4] = val
        descs[i][2] = bytes(d)
    blob, _ = M.finex_mint([tuple(x) for x in descs], int(p["second"]),
                           max_steps=60_000_000)
    return list(struct.unpack(">48I", blob))[4:]


def _bits(words):
    """44 words -> list of 1408 ints (0/1), MSB-first within each word."""
    out = []
    for w in words:
        for b in range(32):
            out.append((w >> (31 - b)) & 1)
    return out


def _words(bits):
    out = []
    for j in range(44):
        v = 0
        for b in range(32):
            v = (v << 1) | bits[j * 32 + b]
        out.append(v)
    return out


def gf2_inv_rows(mat, n):
    """mat: list of n row bitmasks (n columns) -> rows of the inverse."""
    m = [mat[i] | (1 << (n + i)) for i in range(n)]
    for col in range(n):
        p = None
        for r in range(col, n):
            if (m[r] >> col) & 1:
                p = r
                break
        if p is None:
            return None                      # singular
        m[col], m[p] = m[p], m[col]
        for r in range(n):
            if r != col and (m[r] >> col) & 1:
                m[r] ^= m[col]
    return [(m[i] >> n) & ((1 << n) - 1) for i in range(n)]


def build():
    rng = random.Random(SEED)
    vecs = []
    while len(vecs) < NSAMP:
        v = rng.getrandbits(NB)
        if v:
            vecs.append(v)
    patches = [dict((ACTIVE[n], struct.pack(">I", 0)) for n in range(NW))]  # zero
    for v in vecs:
        p = {}
        for n in range(NW):
            p[ACTIVE[n]] = struct.pack(">I", (v >> (32 * n)) & 0xFFFFFFFF)
        patches.append(p)
    with ProcessPoolExecutor(max_workers=16) as pool:
        res = list(pool.map(_run, patches))
    c = res[0]
    bodies = res[1:]

    # V: row k = vecs[k]
    Vrows = vecs
    inv = gf2_inv_rows(Vrows, NB)
    if inv is None:
        print("V singular - need more samples")
        return

    # L_b for every output bit b: L_b = B_b . V^-1
    B = [_bits(bd) for bd in bodies]              # 256 x 1408
    cols = []
    for j in range(NOB):
        bvec = 0
        for k in range(NSAMP):
            if B[k][j]:
                bvec ^= inv[k]
        cols.append(bvec)
    model = {"row": ROW, "c": c, "cols": cols, "active": [list(a) for a in ACTIVE],
             "vecs": vecs}
    json.dump(model, open(os.path.join(HERE, "model_row7.json"), "w"))

    # verify on fresh random vectors
    ok = 0
    tot = 0
    for _ in range(6):
        v = rng.getrandbits(NB)
        p = {ACTIVE[n]: struct.pack(">I", (v >> (32 * n)) & 0xFFFFFFFF)
             for n in range(NW)}
        bd = _run(p)
        pred = list(c)
        for n in range(NW):
            x = (v >> (32 * n)) & 0xFFFFFFFF
            if not x:
                continue
            for b in range(32):
                if (x >> (31 - b)) & 1:
                    m = cols[32 * n + b]
                    for j in range(NOB):
                        if (m >> j) & 1:
                            pred[j >> 5] ^= 1 << (31 - (j & 31))
        tot += 1
        ok += (pred == bd)
        if pred != bd:
            bad = [i for i in range(44) if pred[i] != bd[i]]
            print("  MISMATCH at words", bad[:10])
    print("model verify: %d/%d exact" % (ok, tot))


if __name__ == "__main__":
    build()
