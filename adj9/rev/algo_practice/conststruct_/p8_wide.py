"""Pass 8: identify byte map F (22 known values) against a wide battery."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_common import *

def gmul_gen(a, b, poly):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        a = ((a << 1) ^ poly) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return p

def rotl8(x, n):
    n %= 8
    return x if n == 0 else ((x << n) | (x >> (8 - n))) & 0xFF

def rev8(x):
    return int(f"{x:08b}"[::-1], 2)

def build_sbox(poly, aff_vec, aff_const):
    """S(x) = aff_vec applied to inverse(x) ^ aff_const; aff_vec as tuple of
    rotation amounts to XOR."""
    out = []
    for v in range(256):
        inv = 0
        if v:
            r, base, e = 1, v, 254
            while e:
                if e & 1: r = gmul_gen(r, base, poly)
                base = gmul_gen(base, base, poly); e >>= 1
            inv = r
        y = inv
        for k in aff_vec:
            y ^= rotl8(inv, k)
        out.append(y ^ aff_const)
    return out

AES_SBOX = build_sbox(0x1B, (1, 2, 3, 4), 0x63)
INVS = [0]*256
for i, v in enumerate(AES_SBOX): INVS[v] = i

# SM4 s-box (standard published table)
SM4 = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c052b67171e4578f10d4b0d6a8b"
    "4ab25f0d6f8b4d2c795e8fa0ec41d147a1e0b5c34f6709b3a8d2c5e6"
    "f41a7b9c8d0e3f25164789abcedf01"
) if False else None
# (build SM4 from definition instead: inverse in GF(2^8) poly 0x165? use
#  published table to be safe)
SM4 = bytes([
0xD6,0x90,0xE9,0xFE,0xCC,0xE1,0x3D,0xB7,0x16,0xB6,0x14,0xC2,0x28,0xFB,0x2C,0x05,
0x2B,0x67,0x9A,0x76,0x2A,0xBE,0x04,0xC3,0xAA,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9C,0x42,0x50,0xF4,0x91,0xEF,0x98,0x7A,0x33,0x54,0x0B,0x43,0xED,0xCF,0xAC,0x62,
0xE4,0xB3,0x1C,0xA9,0xC9,0x08,0xE8,0x95,0x80,0xDF,0x94,0xFA,0x75,0x8F,0x3F,0xA6,
0x47,0x07,0xA7,0xFC,0xF3,0x73,0x17,0xBA,0x83,0x59,0x3C,0x19,0xE6,0x85,0x4F,0xA8,
0x68,0x6B,0x81,0xB2,0x71,0x64,0xDA,0x8B,0xF8,0xEB,0x0F,0x4B,0x70,0x56,0x9D,0x35,
0x1E,0x24,0x0E,0x5E,0x63,0x58,0xD1,0xA2,0x25,0x22,0x7C,0x3B,0x01,0x21,0x78,0x87,
0xD4,0x00,0x46,0x57,0x9F,0xD3,0x27,0x52,0x4C,0x36,0x02,0xE7,0xA0,0xC4,0xC8,0x9E,
0xEA,0xBF,0x8A,0xD2,0x40,0xC7,0x38,0xB5,0xA3,0xF7,0xF2,0xCE,0xF9,0x61,0x15,0xA1,
0xE0,0xAE,0x5D,0xA4,0x9B,0x34,0x1A,0x55,0xAD,0x93,0x32,0x30,0xF5,0x8C,0xB1,0xE3,
0x1D,0xF6,0xE2,0x2E,0x82,0x66,0xCA,0x60,0xC0,0x29,0x23,0xAB,0x0D,0x53,0x4E,0x6F,
0xD5,0xDB,0x37,0x45,0xDE,0xFD,0x8E,0x2F,0x03,0xFF,0x6A,0x72,0x6D,0x6C,0x5B,0x51,
0x8D,0x1B,0xAF,0x92,0xBB,0xDD,0xBC,0x7F,0x11,0xD9,0x5C,0x41,0x1F,0x10,0x5A,0xD8,
0x0A,0xC1,0x31,0x88,0xA5,0xCD,0x7B,0xBD,0x2D,0x74,0xD0,0x12,0xB8,0xE5,0xB4,0xB0,
0x89,0x69,0x97,0x4A,0x0C,0x96,0x77,0x7E,0x65,0xB9,0xF1,0x09,0xC5,0x6E,0xC6,0x84,
0x18,0xF0,0x7D,0xEC,0x3A,0xDC,0x4D,0x20,0x79,0xEE,0x5F,0x3E,0xD7,0xCB,0x39,0x48])

W = [int.from_bytes(KB[4*i:4*i+4], "big") for i in range(60)]
s4 = [(W[i-1], W[i] ^ W[i-8] ^ W[i-1]) for i in range(8, 60) if i % 8 == 4]
pairs = {}
for inp, out in s4:
    ib = inp.to_bytes(4, "big"); ob = out.to_bytes(4, "big")
    for j in range(4):
        pairs[ib[j]] = ob[j]
items = sorted(pairs.items())
n = len(items)
print(f"known F: {n} values")

def check(tbl):
    b0 = items[0][1] ^ tbl[items[0][0]]
    return b0 if all(items[k][1] ^ tbl[items[k][0]] == b0 for k in range(1, n)) else None

hits = []
# 1. sbox over any odd modulus, input xored a, output xored b
for poly in range(1, 256, 2):
    sb = build_sbox(poly, (1, 2, 3, 4), 0x00)  # affine const 0, add later
    for a in range(256):
        row = bytes(sb[x ^ a] for x in range(256))
        r = check(row)
        if r is not None:
            hits.append(("sbox", poly, a, r))
print("hits sbox(poly, x^a)^b:", hits[:10])

# 2. AES sbox with different affine rotations: inv ^ rot_k(inv) ^ rot_2k ^ ... ^ c
for poly in (0x1B,):
    invs = [0]*256
    for v in range(1, 256):
        r, base_, e = 1, v, 254
        while e:
            if e & 1: r = gmul_gen(r, base_, poly)
            base_ = gmul_gen(base_, base_, poly); e >>= 1
        invs[v] = r
    for k in range(1, 8):
        base = bytes(invs[v] ^ rotl8(invs[v], k) ^ rotl8(invs[v], 2*k)
                     ^ rotl8(invs[v], 3*k) ^ rotl8(invs[v], 4*k)
                     for v in range(256))
        for a in range(256):
            row = bytes(base[x ^ a] for x in range(256))
            r = check(row)
            if r is not None:
                hits.append(("affine-rot", k, a, r))
print("hits affine-rot:", hits[len(hits):][:10] if hits else [])

# 3. bit-rotated sboxes: F(x) = rotl8(sbox(x^a), n) ^ b
for name, sb in (("AES", AES_SBOX), ("SM4", SM4)):
    for nrot in range(1, 8):
        base = bytes(rotl8(v, nrot) for v in sb)
        for a in range(256):
            row = bytes(base[x ^ a] for x in range(256))
            r = check(row)
            if r is not None:
                hits.append(("rot-sbox", name, nrot, a, r))
print("hits rot-sbox:", [h for h in hits if h[0] == "rot-sbox"][:10])

# 4. direct table matches (no a/b freedom): AES sbox, INVS, SM4, T55
T55 = bytes(v ^ 0x55 for v in AES_SBOX)
for name, tbl in (("AES", AES_SBOX), ("INV", INVS), ("SM4", SM4),
                  ("T55", T55), ("SM4^55", bytes(v ^ 0x55 for v in SM4)),
                  ("SM4-inv", [0]*256 if False else None)):
    if tbl is None: continue
    if isinstance(tbl, list):
        t2 = [0]*256
        for i, v in enumerate(tbl if isinstance(tbl[0], int) else []): pass
    r = check(list(tbl))
    print(f"direct {name}: {r}")

# 5. eyeball tables: F(x)^x, F(x)^AES(x), INVS[F(x)]^x, F(x)^SM4(x)
print("\n x    F    F^x  F^AES INVS[F] SM4(F^?)")
for x, y in items:
    print(f" {x:02x}  {y:02x}  {y^x:02x}  {y^AES_SBOX[x]:02x}  "
          f"{INVS[y]:02x}({INVS[y]^x:02x})  {SM4[x]:02x}({y^SM4[x]:02x})")

# 6. is F^AES_sbox itself bytewise-consistent-with-something? print F composed
#    with AES sbox: G = INVS o F  (i.e., undo AES then apply F?)
print("\nG(x) = INVS[F(x)]:", {f"{x:02x}": f"{INVS[y]:02x}" for x, y in items})
