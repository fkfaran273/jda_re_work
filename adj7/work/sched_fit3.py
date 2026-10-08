"""sched_fit3.py — pin f at i%8==0 (rot amount + rcon table)."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import AES_SBOX

d = json.load(open(os.path.join(HERE, "ks_all2.json")))["keys"]
K = [bytes.fromhex(d["0"][r]) for r in range(14)]
K.append(bytes.fromhex("029901c84ef1c508aa6ac928ebb16bd1"))
W = []
for j in range(14):
    for w in range(4):
        W.append(K[j][4*w:4*w+4])
WI = lambda i: W[i-4]

def rot(t, n):
    n %= 4
    return t[n:] + t[:n]

samples0 = []
for i in range(16, 60):
    if i % 8 == 0:
        inp = bytes(WI(i-1))
        out = bytes(a ^ b for a, b in zip(WI(i), WI(i-8)))
        samples0.append((i, inp, out))

print("=== i%8==0 samples: out ^ SubWord(rot_n(in)) for n=0..3 ===")
for i, inp, out in samples0:
    for n in range(4):
        sw = bytes(AES_SBOX[b] for b in rot(inp, n))
        res = bytes(a ^ b for a, b in zip(out, sw))
        print("  i=%2d rot=%d: %s" % (i, n, res.hex()))
    print()

print("=== also reverse view: out ^ rot_n(SubWord(in)) ===")
for i, inp, out in samples0:
    sw = bytes(AES_SBOX[b] for b in inp)
    for n in range(4):
        res = bytes(a ^ b for a, b in zip(out, rot(sw, n)))
        print("  i=%2d rot=%d: %s" % (i, n, res.hex()))
    print()
