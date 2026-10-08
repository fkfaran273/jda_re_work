"""sched_fit7.py — fit f0 (i%8==0 core) from 6 true-word samples; verify the
full schedule; settle K*_0 vs the record mask."""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import AES_SBOX

d = json.load(open(os.path.join(HERE, "ks_all2.json")))["keys"]
K14 = bytes.fromhex("029901c84ef1c508aa6ac928ebb16bd1")
W = [None] * 60
for r in range(1, 14):
    kb = bytes.fromhex(d["0"][r])
    for w in range(4):
        W[4*r + w] = list(kb[4*w:4*w+4])
for w in range(4):
    W[56 + w] = list(K14[4*w:4*w+4])
sub = lambda t: [AES_SBOX[b] for b in t]

def rot(t, n):
    n %= 4
    return t[n:] + t[:n]

MASK = [0x31, 0x1c, 0xfe, 0xd2]

samples = []
for i in range(16, 60, 8):                    # i%8==0, i>=16
    inp = bytes(W[i-1])
    out = bytes(a ^ b for a, b in zip(W[i], W[i-8]))
    samples.append((i, inp, out))
print("f0 samples (i%8==0):")
for i, inp, out in samples:
    print("  i=%2d in=%s out=%s" % (i, inp.hex(), out.hex()))

def test(name, fn):
    ok = sum(1 for i, inp, out in samples if fn(inp) == out)
    print("  %-40s %d/%d" % (name, ok, len(samples)))
    return ok

test("SubWord ^ MASK", lambda t: bytes(
    a ^ b for a, b in zip(sub(t), MASK)))
test("SubWord ^ MASK rotated 1..3", lambda t: bytes(
    a ^ b for a, b in zip(sub(t), MASK[1:] + MASK[:1])))
for n in range(4):
    test("SubWord(rot%d) ^ MASK" % n, lambda t, n=n: bytes(
        a ^ b for a, b in zip(sub(rot(t, n)), MASK)))
    test("rot%d(SubWord) ^ MASK" % n, lambda t, n=n: bytes(
        a ^ b for a, b in zip(rot(sub(t), n), MASK)))
test("SubWord only", lambda t: bytes(sub(t)))

# residuals for inspection
print("\nresiduals out ^ SubWord(in):")
for i, inp, out in samples:
    print("  i=%2d: %s" % (i, bytes(a ^ b for a, b in zip(out, sub(inp))).hex()))
