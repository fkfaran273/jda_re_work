"""mint2_probe.py — invert mint-0001's body with the 0015-derived keys.
Readable record => the key schedule is a GLOBAL constant."""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import AES_SBOX, AES_INV, gmul, mix_columns, shift_rows

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
K = [bytes(b for w in W[4*r:4*r+4] for b in w) for r in range(15)]
print("K0 (seed half0):", K[0].hex())

def core_inv(C):
    y = unshift(bytes(a ^ b for a, b in zip(C, K[14])))
    for r in range(13, 0, -1):
        y = unshift(imix(bytes(a ^ b for a, b in zip(
            bytes(AES_INV[v] for v in y), K[r]))))
    return bytes(a ^ b for a, b in zip(bytes(AES_INV[v] for v in y), K[0]))

def core(P):
    x = bytes(a ^ b for a, b in zip(P, K[0]))
    x = bytes(AES_SBOX[v] for v in x)
    for r in range(1, 14):
        x = bytes(a ^ b for a, b in zip(mix_columns(shift_rows(x)), K[r]))
        x = bytes(AES_SBOX[v] for v in x)
    return bytes(a ^ b for a, b in zip(shift_rows(x), K[14]))

# sanity: mint 0015 round-trip
blob1 = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
for k in range(3):
    Ck = blob1[16+16*k:32+16*k]
    prev = blob1[:16] if k == 0 else blob1[16*k:16*k+16]
    P = bytes(a ^ b for a, b in zip(core_inv(Ck), prev))
    print("0015 chunk %d P:" % k, P.hex())
    print("   re-encrypt ok:", core(P) == Ck)

blob2 = bytes.fromhex(json.load(open(os.path.join(
    HERE, "..", "..", "adj7_work", "adj7s4_out7.json")))["out_hex"])
print("\nmint 0001 record (cell order):")
for k in range(16):
    Ck = blob2[16+16*k:32+16*k]
    prev = blob2[:16] if k == 0 else blob2[16*k:16*k+16]
    P = bytes(a ^ b for a, b in zip(core_inv(Ck), prev))
    txt = "".join(chr(b) if 32 <= b < 127 else "." for b in P)
    print("  %2d %s |%s|" % (k, P.hex(), txt))
