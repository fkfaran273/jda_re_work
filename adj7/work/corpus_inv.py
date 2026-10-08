"""corpus_inv.py — invert all doodhvale corpus blobs; validate the record law."""
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

# global key schedule from the recovered seed
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

d = json.load(open(os.path.join(HERE, "..", "..", "adj7_work",
                                "adj7_data.json")))
out = []
for rec in d:
    if rec["app"] != "doodhvale_android":
        continue
    blob = bytes.fromhex(rec["sig_hex"])
    header, body = blob[:16], blob[16:272]
    R = b""
    for k in range(16):
        Ck = body[16*k:16*k+16]
        prev = header if k == 0 else body[16*(k-1):16*k]
        P = core_inv(Ck)
        P = bytes(a ^ b for a, b in zip(P, prev))
        R += P
    txt = "".join(chr(b) if 32 <= b < 127 else "\\x%02x" % b for b in R)
    # find JSON end
    end = R.find(b"}")
    tail = R[end+1:end+5].hex() if end >= 0 else None
    pad = R[end+2:] if end >= 0 else b""
    print("sid %s: json_len=%d tail_after_brace=%s a=%s b=%s d=%s"
          % (rec["sid"], (end + 1) if end >= 0 else -1, tail,
             R[8:28].decode(errors="replace"),
             R[36:100].decode(errors="replace"),
             R[174:182].decode(errors="replace") if end and len(R) > 182 else "?"))
    out.append({"sid": rec["sid"], "record": R.hex()})
json.dump(out, open(os.path.join(HERE, "corpus_records.json"), "w"), indent=1)
print("wrote corpus_records.json")
