"""ks_inverse.py — verified CBC inverse for the adj7 body (AES-256 custom law).

Forward (verified): wire = SR(s13) ^ K14; s_r = SBOX(MC(SR(s_{r-1})) ^ K_r);
s_0 = SBOX(P ^ K0); CBC: P_k = record_k ^ C_{k-1}, C_{-1} = IV(header).

    python ks_inverse.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import AES_SBOX

_d = json.load(open(os.path.join(HERE, "record_0015.json")))
K = [bytes.fromhex(k) for k in _d["K"]]
SEED = K[0] + K[1]

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xFF) ^ (0x1B if hi else 0)
        b >>= 1
    return p

MCM_INV = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))
INV = [0] * 256
for i, s in enumerate(AES_SBOX):
    INV[s] = i


def _sr_inv(x):
    """Inverse of spn_round.shift_rows: out[4r+c] = in[4((r+c)%4)+c]
    =>  in[4r+c] = out[4((r-c)%4)+c]."""
    z = [0] * 16
    for r in range(4):
        for c in range(4):
            z[4 * r + c] = x[4 * ((r - c) % 4) + c]
    return z


def _mc_inv(q):
    x = [0] * 16
    for c in range(4):
        col = [q[c * 4 + r] for r in range(4)]
        for r in range(4):
            x[c * 4 + r] = (gmul(MCM_INV[r][0], col[0])
                            ^ gmul(MCM_INV[r][1], col[1])
                            ^ gmul(MCM_INV[r][2], col[2])
                            ^ gmul(MCM_INV[r][3], col[3]))
    return x


def aes_dec_chunk(ct, keys=K):
    x = [ct[i] ^ keys[14][i] for i in range(16)]
    x = _sr_inv(x)                                   # s13
    for rnd in range(13, 0, -1):
        m1 = [INV[b] for b in x]                     # invsub
        q = [m1[i] ^ keys[rnd][i] for i in range(16)]
        srx = _mc_inv(q)
        x = _sr_inv(srx)
    m1_0 = [INV[b] for b in x]
    return bytes(m1_0[i] ^ keys[0][i] for i in range(16))


def cbc_dec(body, iv, keys=K):
    rec, prev = b"", iv
    for k in range(len(body) // 16):
        c = body[16 * k:16 * k + 16]
        rec += bytes(a ^ b for a, b in zip(aes_dec_chunk(c, keys), prev))
        prev = c
    return rec


if __name__ == "__main__":
    blob = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
    rec = cbc_dec(blob[16:272], blob[:16])
    ok = rec == bytes.fromhex(_d["record_0015"])
    print("SANITY doodhvale inverse:", ok)
    import re
    recs = json.load(open(os.path.join(
        HERE, "..", "cap", "nirio_16Feb",
        "nirio_16Feb_oneplus7_newapp_adjust.json")))
    nb = bytes.fromhex(re.search(
        r'signature="([0-9A-Fa-f]+)"',
        next(v for k, v in recs[0]["request_headers"]
             if k.lower() == "authorization")).group(1))
    nrec = cbc_dec(nb[16:272], nb[:16])
    printable = sum(32 <= b < 127 or b in (0, 0x10) for b in nrec)
    print("niri sid27 inverted: printable-ish =", printable, "/256")
    print(repr(nrec[:120]))
    print(repr(nrec[200:]))
