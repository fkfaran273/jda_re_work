"""step2_decrypt.py -- decrypt the 18 niceone bodies two ways:
(a) adj8 Android: AES-256-CBC, key AES_KEY, IV=header
(b) adj9 iOS: the 14-round SPN whitening inverse (CBC from header)
Then check the record layout magic (01 00 08).  Also finish rec2's second.
"""
import sys, json, os

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj8")
import adj8_pure as A
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios")
import adj9ios_pure as P

RECS = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\niceone_records.json"))

# ---------------- (b) SPN inverse (adj9 iOS whitening) ----------------
SBOX_INV = [0] * 256
for i, v in enumerate(P.SBOX):
    SBOX_INV[v] = i
_PI = P._PI


def gf2_inv(rows):
    n = 32
    aug = [(rows[j] << n) | (1 << j) for j in range(n)]
    r = 0
    for c in range(n):
        piv = next(i for i in range(r, n) if (aug[i] >> (n + c)) & 1)
        aug[r], aug[piv] = aug[piv], aug[r]
        for i in range(n):
            if i != r and (aug[i] >> (n + c)) & 1:
                aug[i] ^= aug[r]
        r += 1
    return [aug[j] & ((1 << n) - 1) for j in range(n)]


F_INV_TAB = P._byte_tables(gf2_inv(P.F_ROWS))


def F_inv(chunk):
    return b"".join(P._apply_tab(F_INV_TAB,
                                 int.from_bytes(chunk[4 * b:4 * b + 4],
                                                "little")).to_bytes(4, "little")
                    for b in range(4))


def _pi1_inv(chunk):
    return bytes(chunk[_PI[i]] for i in range(16))


def unwhiten_chunk(chunk, wa):
    x = P._xor(chunk, P._FINAL_KEY)
    for r in range(13, -1, -1):
        if r < 13:
            x = F_inv(x)
        x = _pi1_inv(x)
        x = bytes(SBOX_INV[v] for v in x)
        x = P._xor(x, P._ROUND_KEYS[r])
    return P._xor(x, wa)


def unwhiten(body, header):
    out = bytearray()
    for k in range(len(body) // 16):
        c = body[16 * k:16 * k + 16]
        out += unwhiten_chunk(c, header if k == 0 else body[16 * (k - 1):16 * k])
    return bytes(out)


_r = bytes(range(144))
assert unwhiten(P.whiten_forward(_r, b"\x01" * 16), b"\x01" * 16) == _r
print("[x] SPN inverse round-trip OK")

# ---------------- (a) AES-256-CBC inverse (adj8 Android) ----------------
# forward (adj8_pure._encrypt_chunk), state index = 4*col + row:
#   ARK(RK0); x{13}: SB; out[4c+r] = MC(in[4*((c+r)%4)+r] col); ARK(RKrnd)
#   final: SB; out[4c+r] = in[4*((c+r)%4)+r]; ARK(RK14)
SR_INV = [0] * 16          # SR: out[4c+r] = in[4*((c+r)%4)+r]
for c in range(4):
    for r in range(4):
        SR_INV[4 * ((c + r) % 4) + r] = 4 * c + r


def aes_dec_block(c_in):
    """Inverse of A._encrypt_chunk."""
    RK = A._RK
    x = [c_in[i] ^ RK[14][i] for i in range(16)]
    x = [x[SR_INV[i]] for i in range(16)]            # undo final ShiftRows
    x = [SBOX_INV[b] for b in x]                     # undo final SubBytes
    for rnd in range(13, 0, -1):
        x = [x[i] ^ RK[rnd][i] for i in range(16)]   # undo ARK
        # undo fused MC(SR(.)):  v = MC^-1(cols); in[4j+r] = v[4*((j-r)%4)+r]
        v = [0] * 16
        for c2 in range(4):
            col = [x[c2 * 4 + r] for r in range(4)]
            m = [A._gmul(14, col[0]) ^ A._gmul(11, col[1]) ^ A._gmul(13, col[2]) ^ A._gmul(9, col[3]),
                 A._gmul(9, col[0]) ^ A._gmul(14, col[1]) ^ A._gmul(11, col[2]) ^ A._gmul(13, col[3]),
                 A._gmul(13, col[0]) ^ A._gmul(9, col[1]) ^ A._gmul(14, col[2]) ^ A._gmul(11, col[3]),
                 A._gmul(11, col[0]) ^ A._gmul(13, col[1]) ^ A._gmul(9, col[2]) ^ A._gmul(14, col[3])]
            for r in range(4):
                v[c2 * 4 + r] = m[r]
        for j in range(4):
            for r in range(4):
                x[4 * j + r] = v[4 * ((j - r) % 4) + r]
        x = [SBOX_INV[b] for b in x]                 # undo SubBytes
    return bytes(x[i] ^ RK[0][i] for i in range(16))


_b = os.urandom(16)
assert A._encrypt_chunk(aes_dec_block(_b)) == _b
print("[x] AES-256 inverse round-trip OK\n")


def aes256_cbc_decrypt(body, iv):
    out, prev = bytearray(), iv
    for k in range(0, len(body), 16):
        blk = body[k:k + 16]
        out += bytes(a ^ b for a, b in zip(aes_dec_block(blk), prev))
        prev = blk
    return bytes(out)


# ---------------- rec2 signing second (wide scan) ----------------
hdr2 = bytes.fromhex(RECS[2]["blob_hex"])[:16]
sec2 = None
for off in range(-6000, 6000):
    s = 1778042981 + off
    if P.make_ios_header(s) == hdr2:
        sec2 = s
        break
print("rec2 (GET /attribution) second:", sec2, "\n")

# ---------------- decrypt all bodies both ways ----------------
print(f"{'rec':>4} {'adj8-AES':<18} {'adj9-SPN':<18} winner")
hits = {"aes": 0, "spn": 0}
plains = []
for r in RECS:
    blob = bytes.fromhex(r["blob_hex"])
    hdr, body = blob[:16], blob[16:144]
    pta = aes256_cbc_decrypt(body, hdr)
    pts = unwhiten(body, hdr)
    ma, ms = pta[:3] == b"\x01\x00\x08", pts[:3] == b"\x01\x00\x08"
    hits["aes"] += ma
    hits["spn"] += ms
    plains.append({"i": r["i"], "spn_hex": pts.hex(), "aes_hex": pta.hex()})
    print(f"{r['i']:>4}  {('OK ' + pta[3:19].hex()) if ma else pta[:8].hex():<18} "
          f"{('OK ' + pts[3:19].hex()) if ms else pts[:8].hex():<18}   "
          f"{'AES' if ma else ''}{' SPN' if ms else ''}")

print("\nlayout magic (01 00 08) hits:", hits)
json.dump(plains, open(r"C:\Users\Apps\Downloads\com.penti.app\adj9_ios\work_niceone\_plains.json", "w"), indent=1)
print("saved _plains.json")
