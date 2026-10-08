"""dbg_rt.py — round-trip test of core/core_inv + clean record dump."""
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

# identity tests
x = bytes(range(16))
print("unshift(shift(x)) == x:", unshift(shift_rows(x)) == x)
print("imix(mix(x)) == x     :", bytes(imix(mix_columns(x))) == x)

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

def core(P):
    x = bytes(a ^ b for a, b in zip(P, K[0]))
    x = bytes(AES_SBOX[v] for v in x)
    for r in range(1, 14):
        x = mix_columns(shift_rows(x))
        x = bytes(a ^ b for a, b in zip(x, K[r]))
        x = bytes(AES_SBOX[v] for v in x)
    return bytes(a ^ b for a, b in zip(shift_rows(x), K[14]))

def core_inv(C):
    y = unshift(bytes(a ^ b for a, b in zip(C, K[14])))
    for r in range(13, 0, -1):
        y = unshift(imix(bytes(a ^ b for a, b in zip(
            bytes(AES_INV[v] for v in y), K[r]))))
    return bytes(a ^ b for a, b in zip(bytes(AES_INV[v] for v in y), K[0]))

blob = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
C0 = blob[16:32]
P0 = core_inv(C0)
print("\nR_0 =", P0.hex(), "|%s|" % "".join(chr(b) if 32 <= b < 127 else "." for b in P0))
print("core(P0) == C0:", core(P0) == C0)
if core(P0) != C0:
    a, b = core(P0), C0
    print("  got :", a.hex())
    print("  want:", b.hex())

# full 16-chunk record, mint 0015
print("\nmint 0015 ABSOLUTE record (R_k = core_inv(C_k) ^ C_{k-1}):")
rec = b""
for k in range(16):
    Ck = blob[16+16*k:32+16*k]
    prev = blob[:16] if k == 0 else blob[16*k:16*k+16]
    P = bytes(a ^ b for a, b in zip(core_inv(Ck), prev))
    rec += P
for i in range(0, 256, 32):
    c = rec[i:i+32]
    print("  %02x %s |%s|" % (i, c.hex(),
          "".join(chr(b) if 32 <= b < 127 else "." for b in c)))
json.dump({"record_0015": rec.hex(), "K": [k.hex() for k in K]},
          open(os.path.join(HERE, "record_0015.json"), "w"), indent=1)
print("wrote record_0015.json")
