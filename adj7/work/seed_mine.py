"""seed_mine.py — mine chunk-0 schedule-phase writes for the seed derivation.

Dumps the value sequences at the hot addresses and searches all schedule-phase
writes for any W-word (the 60 AES-256 expansion words) in any byte order.
"""
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
def rot(t, n):
    n %= 4
    return t[n:] + t[:n]
def g(t, i):
    t = rot(t, 1)
    t = [AES_SBOX[b] for b in t]
    r = 1
    for _ in range(i // 8 - 1):
        r = ((r << 1) ^ 0x1B) & 0xFF if r & 0x80 else r << 1
    t[0] ^= r
    return t
W[1] = [a ^ b for a, b in zip(W[9], W[8])]
W[2] = [a ^ b for a, b in zip(W[10], W[9])]
W[3] = [a ^ b for a, b in zip(W[11], W[10])]
W[0] = [a ^ b for a, b in zip(W[8], g(W[7], 8))]
words = [bytes(x) for x in W]
print("W[0..7]:", [w.hex() for w in words[:8]])

# op windows
ops = []
for line in open(os.path.join(HERE, "v9_ops.txt")):
    a, b = line.split()
    ops.append((int(a) + 5300000, int(b, 16)))
s1161 = [i for i, (w, o) in enumerate(ops) if o == 0x1161]
i0 = s1161[0]
i1 = s1161[1]
sched_lo = ops[i0 + 267][0] + 1
sched_hi = ops[i1 - 1][0]
print("chunk-0 schedule window wc:", sched_lo, "..", sched_hi)

# pass over v3_writes.txt
HOT = (0x9005680, 0x9005688, 0x9011670, 0x900b660)
seq = {a: [] for a in HOT}
word_hits = []          # (wc, addr, val) where val matches a W word (any order)
wordset = {}
for n, w in enumerate(words):
    for v in struct.unpack("<I", w) , struct.unpack(">I", w):
        wordset[v[0]] = n
nwr = 0
with open(os.path.join(HERE, "v3_writes.txt")) as f:
    wc = 0
    for line in f:
        wc += 1
        if wc < sched_lo:
            continue
        if wc > sched_hi:
            break
        a, s, v = line.split()
        a = int(a, 16)
        v = int(v, 16)
        nwr += 1
        if a in seq:
            seq[a].append((wc, v))
        if v in wordset:
            word_hits.append((wc, a, v, wordset[v]))
print("schedule-phase writes scanned:", nwr)
for a in HOT:
    s = seq[a]
    print("\nhot %#x: %d writes" % (a, len(s)))
    print("  first 12:", [(w, hex(v)) for w, v in s[:12]])
    print("  last  6 :", [(w, hex(v)) for w, v in s[-6:]])
print("\nW-word dword hits in schedule phase:", len(word_hits))
for wc, a, v, n in word_hits[:20]:
    print("  wc=%d addr=%#x val=%08x -> W[%d]" % (wc, a, v, n))
