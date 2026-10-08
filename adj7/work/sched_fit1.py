"""sched_fit1.py — is the mint-constant schedule a standard AES-256 expansion?

Extracted K1..K13 + true K14 (cell space).  If the VM schedule is standard
AES-256 in SOME lane convention pi (cell order = transposed AES state), the
word recurrence W[i] = W[i-8] ^ g(W[i-1]) holds for i >= 16 using only
K2..K14 (words 8..59).  Test all natural lane maps.  If one passes, recover
the seed (K*_0 = W[0..3]) from K1,K2 and cross-check the whole expansion.
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import AES_SBOX

d = json.load(open(os.path.join(HERE, "ks_all2.json")))["keys"]
K = [bytes.fromhex(d["0"][r]) for r in range(14)]          # K1..K13 (idx0..12)
K.append(bytes.fromhex("029901c84ef1c508aa6ac928ebb16bd1"))  # true K14
# K[j] here = round key K_{j+1}, j=0..13  -> words W[4(j+1) .. 4(j+1)+3]
W = []
for j in range(14):
    for w in range(4):
        W.append(list(K[j][4*w:4*w+4]))                    # W[4..59]


def transpose(b):
    return bytes(b[4*(j % 4) + j//4] for j in range(16))


def dwordrev(b):
    return b"".join(b[4*i:4*i+4][::-1] for i in range(4))


def fullrev(b):
    return b[::-1]


LANES = {
    "id": lambda b: b,
    "T": transpose,
    "D": dwordrev,
    "TD": lambda b: transpose(dwordrev(b)),
    "DT": lambda b: dwordrev(transpose(b)),
    "R": fullrev,
}
# lane inverses (T is an involution, D involution, R involution)
INV = {k: v for k, v in LANES.items()}


def rcon(i):
    v = 1
    for _ in range(i - 1):
        v = ((v << 1) ^ 0x1B) & 0xFF if v & 0x80 else v << 1
    return v


def g(t, i):
    """key-schedule core for word W[i-1] at position i (i counts from 0)."""
    t = t[1:] + t[:1]
    t = [AES_SBOX[b] for b in t]
    t[0] ^= rcon(i // 8)
    return t


def check(lane):
    f = LANES[lane]
    inv = INV[lane]
    Wp = []
    for j in range(14):
        kb = f(K[j])
        for w in range(4):
            Wp.append(list(kb[4*w:4*w+4]))   # Wp[n] = word W[n+4]
    # recurrence test for word index i = 16..59 (Wp[i-4]); needs i-8 >= 4
    ok = 0
    bad = []
    for i in range(16, 60):
        a, b_, c_ = Wp[i-1-4], Wp[i-8-4], Wp[i-4]
        if i % 8 == 0:
            t = g(a, i)
        elif i % 8 == 4:
            t = [AES_SBOX[x] for x in a]
        else:
            t = a
        pred = [c_ if False else b_[j] ^ t[j] for j in range(4)]
        if pred == c_:
            ok += 1
        else:
            bad.append(i)
    return ok, bad, Wp


for lane in LANES:
    ok, bad, Wp = check(lane)
    print("lane %-3s: recurrence %d/44  bad=%s" % (lane, ok, bad[:6]))
