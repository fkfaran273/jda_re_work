"""kb362_probe.py — test whether the 3.62.0 KB362 key block is an AES key
schedule and whether the niri adj7 bodies are AES-CBC (the adj8 law).

  python kb362_probe.py
"""
import hashlib
import hmac
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# ---- AES-256 key expansion (same as adj8_pure) ----
def _xtime(a):
    return ((a << 1) ^ 27) & 255 if a & 128 else (a << 1) & 255

def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p

def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 255

def _affine(y):
    return y ^ _rotl8(y, 1) ^ _rotl8(y, 2) ^ _rotl8(y, 3) ^ _rotl8(y, 4) ^ 99

SBOX = [_affine(0)] + [
    _affine(next(q for q in range(1, 256) if _gmul(v, q) == 1))
    for v in range(1, 256)]

def key_schedule(key):
    W = [list(key[i * 4:i * 4 + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(W[i - 1])
        if i % 8 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        W.append([W[i - 8][j] ^ t[j] for j in range(4)])
    return [[b for w in W[4 * r:4 * r + 4] for b in w] for r in range(15)]

def aes_dec_chunk(rk, chunk):
    """AES decrypt one 16-B block with pre-expanded round keys (Nk rounds)."""
    nr = len(rk) - 1
    x = [chunk[i] ^ rk[nr][i] for i in range(16)]
    for rnd in range(nr - 1, 0, -1):
        # inv shift rows
        y = [0] * 16
        for c in range(4):
            for r in range(4):
                y[((c - r) % 4) * 4 + r] = x[c * 4 + r]
        # inv sub bytes + add round key
        inv = [0] * 256
        for i, s in enumerate(SBOX):
            inv[s] = i
        y = [inv[b] for b in y]
        y = [y[i] ^ rk[rnd][i] for i in range(16)]
        # inv mix columns
        x = [0] * 16
        for c in range(4):
            col = [y[c * 4 + r] for r in range(4)]
            m = [14, 11, 13, 9]
            for r in range(4):
                x[c * 4 + r] = (_gmul(m[r % 4], col[0]) ^ _gmul(m[(r + 3) % 4], col[1])
                                ^ _gmul(m[(r + 2) % 4], col[2]) ^ _gmul(m[(r + 1) % 4], col[3]))
    y = [0] * 16
    for c in range(4):
        for r in range(4):
            y[((c - r) % 4) * 4 + r] = x[c * 4 + r]
    inv = [0] * 256
    for i, s in enumerate(SBOX):
        inv[s] = i
    y = [inv[b] for b in y]
    return bytes(y[i] ^ rk[0][i] for i in range(16))

# ---- load KB362 ----
imm = json.load(open(os.path.join(HERE, "..", "..", "adj7_work",
                                  "adj7s4_immruns.json")))
run = imm["d20a0"]
print("d20a0 run length:", len(run))

def dw2bytes(dws, mask=None, order=">"):
    if mask:
        dws = [d ^ mask for d in dws]
    return b"".join(struct.pack(order + "I", d & 0xFFFFFFFF) for d in dws)

FIPS = struct.pack(">8I", 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
iv_run = imm["ba958"]
for mask in (0xCCCCCCCC, None):
    b = dw2bytes(iv_run, mask)
    print("IV run mask=%s -> %s  fips=%s" % (mask, b.hex()[:32], b == FIPS))

for mask in (0xCCCCCCCC, None):
    for order in (">", "<"):
        kb = dw2bytes(run, mask, order)
        print(f"\n== KB362 mask={mask} order='{order}' first32={kb[:32].hex()}")
        # is the whole block the expansion of its own first 32 bytes?
        sched = key_schedule(kb[:32])
        flat = b"".join(struct.pack("16B", *rk) for rk in sched)  # 240 B
        print("  aes256 schedule match:", flat == kb[:240])
        # as little-endian u32 view?
        kb_le = dw2bytes(run, mask, "<")
        sched_le = key_schedule(kb_le[:32])
        flat_le = b"".join(struct.pack("16B", *rk) for rk in sched_le)
        print("  aes256 schedule match (LE dwords):", flat_le == kb_le[:240])

# ---- try decrypting a niri body ----
recs = json.load(open(os.path.join(HERE, "nirio_16Feb",
                                   "nirio_16Feb_oneplus7_newapp_adjust.json")))
r = recs[0]  # third_party_sharing sid 27
auth = next(v for k, v in r["request_headers"] if k.lower() == "authorization")
blob = bytes.fromhex(__import__("re").search(
    r'signature="([0-9A-Fa-f]+)"', auth).group(1))
header, body = blob[:16], blob[16:272]

kb = dw2bytes(run, 0xCCCCCCCC, ">")
kb_le = dw2bytes(run, 0xCCCCCCCC, "<")
cands = {
    "kb_be_as_sched": [list(kb[i * 16:(i + 1) * 16]) for i in range(16)],
    "kb_le_as_sched": [list(kb_le[i * 16:(i + 1) * 16]) for i in range(16)],
    "sched_from_be_key": key_schedule(kb[:32]),
    "sched_from_le_key": key_schedule(kb_le[:32]),
}
for name, rk in cands.items():
    pt = b""
    wa = header
    for k in range(0, len(body), 16):
        blk = aes_dec_chunk(rk, body[k:k + 16])
        pt += bytes(a ^ b for a, b in zip(blk, wa))
        wa = body[k:k + 16]
    printable = sum(32 <= b < 127 or b in (0, 1, 2, 3, 4, 5, 6, 7) for b in pt)
    print(f"{name:20s} dec head: {pt[:48].hex()}  printable-ish={printable}/256")
