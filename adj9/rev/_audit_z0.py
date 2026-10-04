"""Zone-0 machinery self-check: invert body words 0..3 of a KNOWN 48/48 corpus
row.  If the corpus is INCONSISTENT the zone-0 test is broken and the golden
result means nothing.  Then the SAME test on the golden blobs.
Columns: d0[0], d0[1], d0[2], d4[4] -- the only region words reaching w0-3."""
import base64, json, os, re, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import decoder as D
import mint_pipeline as M

A = json.load(open(os.path.join(HERE, "all_signings.json")))
P = json.load(open(os.path.join(HERE, "pair_h3.json")))
G = json.load(open(os.path.join(HERE, "golden_saz.json")))
ZW = 4
Z = bytes(4)
ZW144 = bytes(144)
ZW32 = bytes(32)

def mint_zone(base_d, d0b, d4b, second):
    out = []
    for bi in M.VA_ORDER:
        b = d0b if bi == 0 else (d4b if bi == 4 else base_d[bi])
        out.append((len(b) // 4, 0, b))
    blob, _i = M.finex_mint(out, second, max_steps=60_000_600)
    return list(struct.unpack(">48I", blob))[4:4 + ZW]

def solve(c, cols, target):
    eqs = []
    for j in range(len(c)):
        for b in range(32):
            mask = 0
            for n in range(len(cols)):
                if (cols[n][j] >> b) & 1:
                    mask |= 1 << (n * 32 + b)
            if mask:
                eqs.append((mask, ((target[j] ^ c[j]) >> b) & 1))
    piv = {}
    bad = False
    for mask, bit in eqs:
        v, b = mask, bit & 1
        while v:
            q = v.bit_length() - 1
            if q in piv:
                pm, pb = piv[q]; v ^= pm; b ^= pb
            else:
                piv[q] = (v, b); break
        else:
            if b:
                bad = True
                break
    if bad:
        return None, len(piv), len(eqs)
    sol = 0
    for q in sorted(piv):
        v, b = piv[q]
        rest = v & ~(1 << q)
        if b ^ (bin(rest & sol).count("1") & 1):
            sol |= 1 << q
    return sol, len(piv), len(eqs)

def zone_test(tag, base_d, d0b, d4b, target, second):
    c = mint_zone(base_d, d0b, d4b, second)
    cols = []
    for slot in range(3):
        v = bytearray(d0b); v[4 * slot] ^= 1
        cols.append(mint_zone(base_d, bytes(v), d4b, second))
    v = bytearray(d4b); v[16] ^= 1
    cols.append(mint_zone(base_d, d0b, bytes(v), second))
    sol, rank, neq = solve(c, cols, target)
    print("%-30s neq=%-4d colrank=%-4d SOLVED=%-5s %s"
          % (tag, neq, rank, sol is not None,
             ["%08x" % ((sol >> (n * 32)) & 0xFFFFFFFF) for n in range(4)]
             if sol is not None else ""), flush=True)
    return sol is not None

def corpus_base(r):
    return {bi: bytes.fromhex(r.get("d%d" % bi, "")) for bi in M.VA_ORDER}

def main():
    r = A[4]
    d = corpus_base(r)
    tgt = list(struct.unpack(">44I", bytes.fromhex(P[4]["blob"])[16:]))[:ZW]
    zone_test("corpus row4 TRUE region", d, d[0], d[4], tgt, int(P[4]["second"]))
    claims = dict(G["s1"]["params"]); claims.update(M.INTERNAL_CLAIMS)
    claims["activity_kind"] = "session"
    dd, _m = M.build_descriptors(claims, "session", ZW144, Z, ZW32)
    gbase = corpus_base(r); gbase[10] = dd[6][2]; gbase[7] = dd[5][2]
    for tag, sec in (("s1", 1788856523), ("s2", 1788856523),
                     ("s3", 1788856526), ("s4", 1788856528)):
        b = base64.b64decode(re.search(r'signature="([^"]+)"',
                                       G[tag]["auth"]).group(1))
        t = list(struct.unpack(">44I", b[16:]))[:ZW]
        zone_test("golden %s zone0-3" % tag, gbase, ZW144, ZW32, t, sec)

if __name__ == "__main__":
    main()
