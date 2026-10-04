"""_z0diag.py — is the golden "inconsistency" an artifact of the all-zero
region base?  Reproduces _audit_z0's column method at THREE base points and
reports colrank / solvability, plus a GF(2) linearity self-check.

Also runs the same 4-column solve with the 128 d8 columns added, to see whether
d8 alone can reach the golden target.
"""
import base64, json, os, re, struct, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M

A = json.load(open(os.path.join(HERE, "all_signings.json")))
P = json.load(open(os.path.join(HERE, "pair_h3.json")))
G = json.load(open(os.path.join(HERE, "golden_saz.json")))
ZW = 4
Z144 = bytes(144); Z32 = bytes(32); Z4 = bytes(4)


def corpus_base(r):
    return {bi: bytes.fromhex(r.get("d%d" % bi, "")) for bi in M.VA_ORDER}


def claims_of(tag, kind="session"):
    c = dict(G[tag]["params"]); c.update(M.INTERNAL_CLAIMS)
    c["activity_kind"] = kind
    return c


def descs(d0, d2, d4, d8, d9, d7, d10, d5=None, d6=None):
    d5 = d5 if d5 is not None else bytes(4)
    d6 = d6 if d6 is not None else bytes(4)
    by = {0: d0, 9: d9, 8: d8, 4: d4, 2: d2, 7: d7, 10: d10, 5: d5, 6: d6,
          1: b"", 3: b""}
    return [(len(by[i]) // 4, 0, by[i]) for i in M.VA_ORDER]


def mint_w(ds, sec):
    blob, _ = M.finex_mint(ds, sec, max_steps=60_000_600)
    return list(struct.unpack(">48I", blob))[4:4 + ZW]


def solve(c, cols, target):
    n = len(cols); eqs = []
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
                pm, pb = piv[q]; v ^= pm; bb ^= pb
            else:
                piv[q] = (v, bb); break
        else:
            if bb:
                return None, len(piv), len(eqs)
    sol = 0
    for q in sorted(piv):
        v, bb = piv[q]
        if bb ^ (bin((v & ~(1 << q)) & sol).count("1") & 1):
            sol |= 1 << q
    return sol, len(piv), len(eqs)


def flip(b, byte, bit):
    v = bytearray(b); v[byte] ^= 1 << bit
    return bytes(v)


def region_cols(ds_fn, d0, d4):
    cols = []
    for k in range(3):
        b = flip(d0, 4 * k, 0)
        cols.append(mint_w(ds_fn(d0b=b), SEC))
    cols.append(mint_w(ds_fn(d4b=flip(d4, 16, 0)), SEC))
    return cols


def run(tag, base, target, d0, d4, d8cols=False):
    def mk(d0b=d0, d4b=d4, d8b=None):
        return descs(d0b, base[2], d4b,
                     d8b if d8b is not None else base[8], base[9],
                     base[7], base[10], base[5], base[6])
    c = mint_w(mk(), SEC)
    cols = region_cols(mk, d0, d4)
    lin = all((c[j] ^ cols[0][j]) ==
              mint_w(mk(d0b=flip(d0, 0, 0)), SEC)[j] for j in range(ZW))
    sol, rank, neq = solve(c, cols, target)
    print("%-34s c=%s rank=%d/%d SOLVED=%s %s  linear=%s" %
          (tag, " ".join("%08x" % w for w in c), rank, neq, sol is not None,
           ("" if sol is None else " ".join("%08x" % ((sol >> (n * 32)) & 0xFFFFFFFF)
                                            for n in range(4))), lin), flush=True)
    return c, cols, rank, neq, sol


r = A[4]
cb = corpus_base(r)
ctgt = list(struct.unpack(">48I", bytes.fromhex(P[4]["blob"])))[4:8]

# --- base 1: corpus TRUE descriptors, TRUE target
ddc, _ = M.build_descriptors(claims_of("s1"), "session", cb[0], cb[2], cb[4])
byc = {i: ddc[k] for k, i in enumerate(M.VA_ORDER)}
CB = {i: byc[i][2] for i in M.VA_ORDER}
SEC = 1788856523
print("== base1: corpus region + GOLDEN claims, target = CORPUS body 4-7")
run("b1 corpus-region/golden-claims", CB, ctgt, cb[0], cb[4])

# --- base 2: corpus region + golden claims, target = GOLDEN s1
b = base64.b64decode(re.search(r'signature="([^"]+)"', G["s1"]["auth"]).group(1))
gtgt = list(struct.unpack(">48I", b))[4:8]
print("== base2: corpus region + golden claims, target = GOLDEN s1 body 4-7")
c2, cols2, rank2, neq2, sol2 = run("b2 corpus-region/golden-claims", CB, gtgt,
                                    cb[0], cb[4])
