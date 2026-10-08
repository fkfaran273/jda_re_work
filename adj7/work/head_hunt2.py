"""head_hunt2.py — find the PRNG draw offset: header = pairXOR(draws[N..N+7]),
record IV = pairXOR(draws[N+8..N+15])?
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
sys.path.insert(0, WORK)
sys.path.insert(0, HERE)
from adj7_signer import BionicRand
from spn_round import AES_SBOX, AES_INV, gmul

def unshift(b):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * ((r + c) % 4) + c] = b[4 * r + c]
    return bytes(out)

def imix(b):
    out = bytearray(16)
    for q in range(4):
        col = b[4*q:4*q+4]
        for i in range(4):
            v = 0
            for j, m in enumerate(((14, 11, 13, 9), (9, 14, 11, 13),
                                   (13, 9, 14, 11), (11, 13, 9, 14))[i]):
                v ^= gmul(col[j], m)
            out[4*q + i] = v
    return bytes(out)

SEED = bytes.fromhex("f110fb41676dba311f38c652c8f951ec"
                     "3db456c07b9166a509bef66cd870654b")
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
Wp = [list(SEED[4*i:4*i+4]) for i in range(8)]
for i in range(8, 60):
    t = g(Wp[i-1], i) if i % 8 == 0 else (
        [AES_SBOX[b] for b in Wp[i-1]] if i % 8 == 4 else Wp[i-1])
    Wp.append([Wp[i-8][j] ^ t[j] for j in range(4)])
K = [bytes(b for w in Wp[4*r:4*r+4] for b in w) for r in range(15)]

def core_inv(C):
    y = unshift(bytes(a ^ b for a, b in zip(C, K[14])))
    for r in range(13, 0, -1):
        y = unshift(imix(bytes(a ^ b for a, b in zip(
            bytes(AES_INV[v] for v in y), K[r]))))
    return bytes(a ^ b for a, b in zip(bytes(AES_INV[v] for v in y), K[0]))

def pxor(d):
    return b"".join((d[2*i] ^ d[2*i+1]).to_bytes(4, "big") for i in range(len(d)//2))

data = {r["sid"]: r for r in json.load(
    open(os.path.join(WORK, "adj7_data.json"))) if r["app"] == "doodhvale_android"}
recs = json.load(open(os.path.join(HERE, "corpus_records.json")))

for cr in recs[:6]:
    sid = cr["sid"]
    R = bytes.fromhex(cr["record"])          # inverted with IV=header
    blob = bytes.fromhex(data[sid]["sig_hex"])
    header = blob[:16]
    sec = int(data[sid]["created_at"])
    Rg = BionicRand(sec)
    draws = [Rg.next() for _ in range(400)]
    # find N: pairXOR(draws[N:N+8]) == header
    Ns = [n for n in range(0, 380) if pxor(draws[n:n+8]) == header]
    print("sid", sid, "sec", sec, "header-draw offset N:", Ns[:4])
    if not Ns:
        continue
    N = Ns[0]
    iv_cand = pxor(draws[N+8:N+16])
    C0 = blob[16:32]
    P0 = bytes(a ^ b for a, b in zip(core_inv(C0), iv_cand))
    print("   IV(N+8..N+15) =", iv_cand.hex())
    print("   P0 =", P0, "|%s|" % "".join(chr(b) if 32 <= b < 127 else "." for b in P0))
    # also try IV=0
    P0z = core_inv(C0)
    print("   IV=0        P0 |%s|" % "".join(chr(b) if 32 <= b < 127 else "." for b in P0z))
