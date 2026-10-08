"""decrypt_rec.py -- decrypt a genuine adj7 blob body with the known key
schedule (inverse SPN) and print the recovered 256-B record."""
import json, re, sys

sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
import adj7_pure as sg

SBOX_INV = bytes(256)
_inv = [0] * 256
for i in range(256):
    _inv[sg.AES_SBOX[i]] = i
SBOX_INV = bytes(_inv)

def invSR(b):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r - c) % 4) + c]
    return bytes(out)

_IMC = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))

def invMC(b):
    out = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= sg._gmul(col[j], _IMC[i][j])
            out[4 * q + i] = v
    return bytes(out)

def spn_inv(C, keys=sg._RK):
    x = bytes(a ^ b for a, b in zip(C, keys[14]))
    x = invSR(x)
    for r in range(12, -1, -1):
        x = bytes(SBOX_INV[v] for v in x)
        x = bytes(a ^ b for a, b in zip(x, keys[1 + r]))
        x = invMC(x)
        x = invSR(x)
    x = bytes(SBOX_INV[v] for v in x)
    return bytes(a ^ b for a, b in zip(x, keys[0]))

def cbc_decrypt(body, header, keys=sg._RK):
    out, prev = b"", header
    for k in range(0, len(body), 16):
        P = spn_inv(body[k:k + 16], keys)
        out += bytes(a ^ b for a, b in zip(P, prev))
        prev = body[k:k + 16]
    return out

if __name__ == "__main__":
    D = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json"))
    sid = sys.argv[1] if len(sys.argv) > 1 else "44"
    CAP = next(e for e in D if str(e["sid"]) == sid)
    auth = None
    for k, v in CAP["request_headers"]:
        if k.lower() == "authorization":
            auth = v
    blob = bytes.fromhex(re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1))
    rec = cbc_decrypt(blob[16:272], blob[:16])
    print("record[0:128]:", rec[:128])
    print()
    print(repr(rec[:160]))
