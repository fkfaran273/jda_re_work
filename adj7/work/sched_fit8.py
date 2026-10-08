"""sched_fit8.py — wide battery for f0 (i%8==0 core), 6 samples."""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import AES_SBOX, gmul, mix_columns, shift_rows

d = json.load(open(os.path.join(HERE, "ks_all2.json")))["keys"]
K14 = bytes.fromhex("029901c84ef1c508aa6ac928ebb16bd1")
W = [None] * 60
for r in range(1, 14):
    kb = bytes.fromhex(d["0"][r])
    for w in range(4):
        W[4*r + w] = list(kb[4*w:4*w+4])
for w in range(4):
    W[56 + w] = list(K14[4*w:4*w+4])
sub = lambda t: bytes(AES_SBOX[b] for b in t)

def rot(t, n):
    n %= 4
    return t[n:] + t[:n]

def mc_col(c):
    """MixColumns on one 4-B column (standard MCM)."""
    out = []
    for i in range(4):
        v = 0
        for j in range(4):
            v ^= gmul(c[j], ((2, 3, 1, 1), (1, 2, 3, 1),
                             (1, 1, 2, 3), (3, 1, 1, 2))[i][j])
        out.append(v)
    return bytes(out)

def imc_col(c):
    out = []
    for i in range(4):
        v = 0
        for j in range(4):
            v ^= gmul(c[j], ((14, 11, 13, 9), (9, 14, 11, 13),
                             (13, 9, 14, 11), (11, 13, 9, 14))[i][j])
        out.append(v)
    return bytes(out)

samples = []
for i in range(16, 60, 8):
    inp = bytes(W[i-1])
    out = bytes(a ^ b for a, b in zip(W[i], W[i-8]))
    samples.append((i, inp, out))

def test(name, fn):
    ok = sum(1 for i, inp, out in samples if fn(inp) == out)
    print("  %-44s %d/%d" % (name, ok, len(samples)))
    return ok

print("=== battery ===")
test("MC(SubWord(in))", lambda t: mc_col(sub(t)))
test("MC(SubWord(in)) bytes reversed", lambda t: mc_col(sub(t))[::-1])
for n in range(4):
    test("MC(SubWord(rot%d))" % n, lambda t, n=n: mc_col(sub(rot(t, n))))
    test("rot%d(MC(SubWord))" % n, lambda t, n=n: rot(mc_col(sub(t)), n))
    test("IMC(SubWord(rot%d))" % n, lambda t, n=n: imc_col(sub(rot(t, n))))
    test("SubWord(rot%d)" % n, lambda t, n=n: sub(rot(t, n)))
test("IMC(SubWord)", lambda t: imc_col(sub(t)))
test("SubWord then *2 each byte", lambda t: bytes(gmul(b, 2) for b in sub(t)))
test("SubWord then *3 each byte", lambda t: bytes(gmul(b, 3) for b in sub(t)))

# residual structure: out ^ SubWord(rot_n(in)) for n=0..3
print("\nresiduals out ^ SubWord(rot_n(in)):")
for i, inp, out in samples:
    row = []
    for n in range(4):
        row.append(bytes(a ^ b for a, b in zip(out, sub(rot(inp, n)))).hex())
    print("  i=%2d  %s" % (i, "  ".join(row)))
print("\nresiduals out ^ MC(SubWord(rot_n(in))):")
for i, inp, out in samples:
    row = []
    for n in range(4):
        row.append(bytes(a ^ b for a, b in zip(out, mc_col(sub(rot(inp, n))))).hex())
    print("  i=%2d  %s" % (i, "  ".join(row)))

# per-byte check: is out[j] = SBOX[in[p(j)]] ^ c(j) for fixed permutation p?
print("\nper-byte SBOX mapping test:")
for j in range(4):
    for p in range(4):
        consts = set()
        ok = True
        for i, inp, out in samples:
            c = out[j] ^ AES_SBOX[inp[p]]
            consts.add(c)
        if len(consts) == 1:
            print("  out[%d] = SBOX[in[%d]] ^ %02x  (all 6)" % (j, p, consts.pop()))
# also allow gmul by 2/3 on the sbox output
for j in range(4):
    for p in range(4):
        for m in (1, 2, 3, 9, 11, 13, 14):
            consts = set()
            for i, inp, out in samples:
                consts.add(out[j] ^ gmul(AES_SBOX[inp[p]], m))
            if len(consts) == 1:
                print("  out[%d] = gm%d(SBOX[in[%d]]) ^ %02x" % (j, m, p, consts.pop()))
