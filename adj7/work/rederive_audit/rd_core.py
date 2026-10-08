"""Fresh-eyes crypto verification of the adj7 CLAIMS law.

Independent implementations:
  - sha256 with custom IV (own compression function, cross-checked vs hashlib)
  - AES-256 SPN inverse (decrypt) matching the measured law (no final SBOX,
    measured ShiftRows), cross-checked by re-encrypting with adj7_pure
Per row:
  1. split blob = header(16) || body(256) || tag(32); verify tag HMAC-SHA256(DK37, body)
  2. decrypt body -> record plaintext
  3. verify record template BYTE-FOR-BYTE (spacing, rjust-20, 0x10 padding)
  4. H_device, nonce12, cert40 from the record
  5. claims candidates -> H via own sha256-iv0 -> match?
"""
import json, hashlib, hmac, os, sys, struct

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj7_pure as ap

DK37 = bytes.fromhex("2a4cc07960d647623cc386dcefafbf25b669914d32cc8585a1ed7f920ef591eb")
IV0 = (0x16ba6d02, 0x11a298c2, 0x82187e46, 0x4c148c22,
       0x3a5cbc15, 0x06519f14, 0x97b9e370, 0x08ec3bec)

# ---------------- independent sha256 with custom IV --------------------
_K = []
for i in range(64):
    c = struct.unpack(">I", __import__("binascii").unhexlify(
        "428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f19234ea82d6aabc4c"
        "d807aa9812835b01243185be550c7dc372be5d7480deb1fe9bdc06a7c19bf174"
        "e49b69c1efbe47860fc19dc6240670772de92c6f4a7484aa5cb0a9dc76f988a1"
        "983e5152a831c66d00327c8b45300b329fbf4a831c24b8b7076ca97c1c19b423"
        "d5e2b0a34ad1fa2f5565a9105c2b8a24a45dc7ad927a6d8b7f5442e34e10b5c1"
        "6ca2774c1429296705b0a8fc1f837e42607d9baa21e1cde6c33707d6d4b380d7"
        "9b83a0ccba2ce1c37c16fbb0943548abf2d19f5f6841516e54882f48831c2b8e"
        "bef52581b00327c8bf597fc7c6e00bf3d5a7914706ca6351142929670a4a8ea1"
        "2748774c34b0bcb5391c0cb34ed8aa4a5b9c4f6e68215afa6829b6ac0d161b2b"
        "748f82ee78a5636f84c878148cc7020890befffaa4506cebbef9a3f7c67178f2".encode()
    )[i]) if False else None

# simpler: derive K the textbook way (fractional cube roots of first 64 primes)
def _primes(n):
    out, i = [], 2
    while len(out) < n:
        if all(i % p for p in out if p * p <= i):
            out.append(i)
        i += 1
        if i > 400: break
    return out

import math
def _kconst(p):
    c = math.cbrt(p)
    f = math.floor((c - math.floor(c)) * (1 << 32))
    return f
_KC = [_kconst(p) for p in _primes(64)]
_M = 0xFFFFFFFF
def _rotr(x, n): return ((x >> n) | (x << (32 - n))) & _M

def _compress(state, blk16):
    w = list(blk16)
    for i in range(16, 64):
        x, y = w[i-15], w[i-2]
        s0 = _rotr(x,7) ^ _rotr(x,18) ^ (x >> 3)
        s1 = _rotr(y,17) ^ _rotr(y,19) ^ (y >> 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & _M)
    a,b,c,d,e,f,g,h = state
    for i in range(64):
        s1 = _rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25)
        t1 = (h + s1 + ((e & f) ^ ((~e & _M) & g)) + _KC[i] + w[i]) & _M
        s0 = _rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22)
        t2 = (s0 + ((a & b) ^ (a & c) ^ (b & c))) & _M
        h,g,f = g,f,e
        e = (d + t1) & _M
        d,c,b = c,b,a
        a = (t1 + t2) & _M
    return [(x + st) & _M for x, st in zip((a,b,c,d,e,f,g,h), state)]

def sha256_iv(msg, iv):
    padded = msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64) + struct.pack(">Q", len(msg) * 8)
    state = list(iv)
    for i in range(0, len(padded), 64):
        state = _compress(state, struct.unpack(">16I", padded[i:i+64]))
    return struct.pack(">8I", *state)

STD_IV = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
# sanity: standard IV round-trip vs hashlib
for m in (b"", b"abc", b"x" * 55, b"y" * 56, b"z" * 200, bytes(range(256))):
    assert sha256_iv(m, STD_IV) == hashlib.sha256(m).digest(), m
print("sanity: independent sha256(iv) matches hashlib for standard IV")

def H_of(claims: bytes, nonce12: bytes, cert40: bytes) -> bytes:
    return sha256_iv(cert40 + nonce12 + ap.SHA0_HEX.encode() + claims, IV0)

# ---------------- independent AES-256 decrypt (measured law) -----------
SBOX = ap.AES_SBOX
SBOX_I = [0]*256
for i, v in enumerate(SBOX):
    SBOX_I[v] = i
SBOX_I = bytes(SBOX_I)
RK = ap._RK

def _sr_inv(b):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4*r + c] = b[4*((r - c) % 4) + c]
    return bytes(out)

_MCM_I = ((14,11,13,9),(9,14,11,13),(13,9,14,11),(11,13,9,14))
def _mc_inv(b):
    out = bytearray(16)
    for q in range(4):
        col = b[4*q:4*q+4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= ap._gmul(col[j], _MCM_I[i][j])
            out[4*q + i] = v
    return bytes(out)

def spn_inv(C, keys=RK):
    x = bytes(a ^ b for a, b in zip(C, keys[14]))
    x = _sr_inv(x)
    for r in range(12, -1, -1):
        x = bytes(SBOX_I[v] for v in x)
        x = bytes(a ^ b for a, b in zip(x, keys[1 + r]))
        x = _mc_inv(x)
        x = _sr_inv(x)
    x = bytes(SBOX_I[v] for v in x)
    return bytes(a ^ b for a, b in zip(x, keys[0]))

def cbc_decrypt(body, header):
    out, prev = b"", header
    for k in range(0, len(body), 16):
        c = body[k:k+16]
        out += bytes(a ^ b for a, b in zip(spn_inv(c), prev))
        prev = c
    return out

# ---------------- record template check (byte-for-byte) ----------------
def parse_record(rec: bytes):
    info = {"len": len(rec)}
    pos = 0
    def take(n, expect=None, label=""):
        nonlocal pos
        chunk = rec[pos:pos+n]
        pos += n
        if expect is not None:
            info["ok_" + label] = (chunk == expect)
        return chunk
    info["lit1"] = take(8, b'{ "a":  ', "lit1")            # '{ "a":  '
    A = take(20, label="A")
    info["A"] = A
    info["ok_A_rjust20"] = (len(A) == 20 and A[0:1] in b" 0123456789" and A.strip().isdigit()
                            and A == A.decode().rjust(20).encode())
    info["lit2"] = take(8, b' ,"b": "', "lit2")            # ' ,"b": "'
    info["H"] = take(64, label="H")
    info["lit3"] = take(8, b'","c": "', "lit3")            # '","c": "'
    info["cert40"] = take(40, label="cert40")
    info["lit4"] = take(8, b'","d": "', "lit4")            # '","d": "'
    info["d8"] = take(8, label="d8")
    info["lit5"] = take(8, b'","e": "', "lit5")            # '","e": "'
    info["e"] = take(64, label="e")
    info["lit6"] = take(4, b'" }\x00', "lit6")             # '" }\x00'
    pad = rec[pos:]
    info["pad_len"] = len(pad)
    info["pad_all_0x10"] = all(b == 0x10 for b in pad)
    info["ok"] = all(v for k, v in info.items() if k.startswith("ok_")) and info["pad_all_0x10"]
    return info

