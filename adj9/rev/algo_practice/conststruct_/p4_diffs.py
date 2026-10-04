"""Pass 4: test the AES-256 schedule family on KB words, both byte orders.

For stride-8 schedules:
  i%8 in {1,2,3,5,6,7}:  d[i] = w[i]^w[i-8] should be g(w[i-1])
  i%8 == 4:              d[i] = Sub(w[i-1])
  i%8 == 0:              d[i] = Sub(Rot(w[i-1])) ^ rcon
Also test stride-4 (AES-128-like) on 60 words.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_common import *

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return p

def aes_sbox():
    out = []
    for v in range(256):
        inv = 0 if v == 0 else pow(v, 254, 0x11B) if False else None
        # proper inverse via exponentiation in GF(2^8)
        r, base, e = 1, v, 254
        if v == 0:
            out.append(0x63); continue
        while e:
            if e & 1: r = gmul(r, base)
            base = gmul(base, base); e >>= 1
        inv = r
        def rotl8(x, n): return ((x << n) | (x >> (8 - n))) & 0xFF
        out.append(inv ^ rotl8(inv,1) ^ rotl8(inv,2) ^ rotl8(inv,3) ^ rotl8(inv,4) ^ 0x63)
    return out
SBOX = aes_sbox()
INV_SBOX = [0]*256
for i, v in enumerate(SBOX): INV_SBOX[v] = i

RCON = [0x01]
for _ in range(15): RCON.append(gmul(RCON[-1], 2))

def rot_word(w, endian="big"):
    b = list(w.to_bytes(4, endian))
    return int.from_bytes(bytes(b[1:] + b[:1]), endian)

def sub_word(w, sbox, endian="big"):
    return int.from_bytes(bytes(sbox[x] for x in w.to_bytes(4, endian)), endian)

for endian in ("big", "little"):
    W = [int.from_bytes(KB[4*i:4*i+4], endian) for i in range(60)]
    print(f"\n############ words parsed {endian}-endian ############")

    # 1. plain-linear check at non-sub positions
    print("-- stride 8: d[i] vs w[i-1] --")
    for i in range(8, 60):
        d = W[i] ^ W[i-8]
        eq_plain = (d == W[i-1])
        print(f"  i={i:2d} m8={i%8} d={d:08x} w[i-1]={W[i-1]:08x} "
              f"plain={eq_plain} d^w[i-1]={d ^ W[i-1]:08x}")
