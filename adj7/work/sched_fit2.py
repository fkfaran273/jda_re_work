"""sched_fit2.py — fit the key-schedule core f at i%8 in {0,4}.

Known: W[i] = W[i-8] ^ f(W[i-1]) with f = identity for i%8 not in {0,4}.
Samples: f(W[i-1]) = W[i] ^ W[i-8] for i%8 in {0,4}, i >= 12 (i=8 needs W[0]).
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import AES_SBOX

d = json.load(open(os.path.join(HERE, "ks_all2.json")))["keys"]
K = [bytes.fromhex(d["0"][r]) for r in range(14)]
K.append(bytes.fromhex("029901c84ef1c508aa6ac928ebb16bd1"))   # true K14
W = []                                                       # W[4..59]
for j in range(14):
    for w in range(4):
        W.append(K[j][4*w:4*w+4])
WI = lambda i: W[i-4]                                        # word getter

print("=== f samples (i, i%8, in=W[i-1], out=W[i]^W[i-8]) ===")
samples = []
for i in range(12, 60):
    if i % 8 in (0, 4):
        inp, out = bytes(WI(i-1)), bytes(a ^ b for a, b in zip(WI(i), WI(i-8)))
        samples.append((i, inp, out))
        print("i=%2d mod8=%d in=%s out=%s" % (i, i % 8, inp.hex(), out.hex()))

def rot(t, n):
    n %= 4
    return t[n:] + t[:n]

print("\n=== hypothesis tests on samples ===")
def test(name, fn):
    ok = sum(1 for i, inp, out in samples if fn(inp, i) == out)
    print("  %-42s %d/%d" % (name, ok, len(samples)))
    return ok

test("SubWord only", lambda t, i: bytes(AES_SBOX[b] for b in t))
for n in range(4):
    test("RotWord+%d then SubWord" % n,
         lambda t, i, n=n: bytes(AES_SBOX[b] for b in rot(t, n)))
    test("SubWord then Rot+%d" % n,
         lambda t, i, n=n: rot(bytes(AES_SBOX[b] for b in t), n))
test("SubWord+Rot1+Rcon1",
     lambda t, i: bytes(x ^ y for x, y in zip(
         (AES_SBOX[b] for b in rot(t, 1)), (1, 0, 0, 0))))
test("SubWord+Rot1+Rcon(i//8)",
     lambda t, i: bytes(x ^ y for x, y in zip(
         (AES_SBOX[b] for b in rot(t, 1)),
         (rcon_v(i//8), 0, 0, 0))))
test("SubWord+Rcon1 no rot",
     lambda t, i: bytes(x ^ y for x, y in zip(
         (AES_SBOX[b] for b in t), (1, 0, 0, 0))))

def rcon_v(n):
    v = 1
    for _ in range(n - 1):
        v = ((v << 1) ^ 0x1B) & 0xFF if v & 0x80 else v << 1
    return v

print("\n=== out ^ SubWord(in) / out ^ SubWord(Rot1(in)) dumps ===")
for i, inp, out in samples[:6]:
    sw = bytes(AES_SBOX[b] for b in inp)
    swr = bytes(AES_SBOX[b] for b in rot(inp, 1))
    print("i=%2d out^SW    = %s" % (i, bytes(a ^ b for a, b in zip(out, sw)).hex()))
    print("i=%2d out^SWRot= %s" % (i, bytes(a ^ b for a, b in zip(out, swr)).hex()))
