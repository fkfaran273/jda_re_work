"""Pass 5: crack the full affine key schedule.

Known so far (BE and LE both):  for i%8 in {1,2,3,5,6,7}:
    w[i] = w[i-8] ^ w[i-1] ^ 0x55555555
Remaining: the map at i%8==4 (no rcon) and i%8==0 (with rcon).
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

def rotl8(x, n): return ((x << n) | (x >> (8 - n))) & 0xFF

def build_sbox(aff=0x63):
    out = []
    for v in range(256):
        if v == 0:
            inv = 0
        else:
            r, base, e = 1, v, 254
            while e:
                if e & 1: r = gmul(r, base)
                base = gmul(base, base); e >>= 1
            inv = r
        out.append(inv ^ rotl8(inv,1) ^ rotl8(inv,2) ^ rotl8(inv,3)
                   ^ rotl8(inv,4) ^ aff)
    return out

SBOX = build_sbox()

RCON = [1]
for _ in range(20): RCON.append(gmul(RCON[-1], 2))

for endian in ("big", "little"):
    W = [int.from_bytes(KB[4*i:4*i+4], endian) for i in range(60)]
    print(f"########## {endian}-endian ##########")

    # 1. verify the plain law at i%8 in {1,2,3,5,6,7}
    bad = [i for i in range(8, 60)
           if i % 8 in (1, 2, 3, 5, 6, 7)
           and W[i] != W[i-8] ^ W[i-1] ^ 0x55555555]
    print(f"plain law w[i]=w[i-8]^w[i-1]^0x55555555 violations: {bad}")

    # 2. i%8==4 samples: map in=w[i-1] -> out=d[i]^w[i-1]
    s4 = [(W[i-1], W[i] ^ W[i-8] ^ W[i-1]) for i in range(8, 60) if i % 8 == 4]
    print(f"\ni%8==4 samples ({len(s4)}):")
    for a, b in s4: print(f"    in={a:08x} out={b:08x}")

    # byte-level mapping test: does out byte j depend only on in byte j?
    # with 6 samples we check consistency of one global bytewise map:
    print("  byte-j pairing (in_byte -> out_byte):")
    for j in range(4):
        sh = 8 * (3 - j) if endian == "big" else 8 * j
        pairs = [((a >> sh) & 0xFF, (b >> sh) & 0xFF) for a, b in s4]
        print(f"    byte{j}: " + " ".join(f"{x:02x}->{y:02x}" for x, y in pairs))
        # compare with AES sbox and sbox^c
        for name, tbl in (("sbox", SBOX),):
            diffs = {y ^ tbl[x] for x, y in pairs}
            print(f"      out^{name}(in) distinct: {sorted(hex(d) for d in diffs)}")

    # 3. i%8==0 samples
    s0 = [(W[i-1], W[i] ^ W[i-8] ^ W[i-1]) for i in range(8, 60) if i % 8 == 0]
    print(f"\ni%8==0 samples ({len(s0)}):")
    for a, b in s0: print(f"    in={a:08x} out={b:08x}")
    for j in range(4):
        sh = 8 * (3 - j) if endian == "big" else 8 * j
        pairs = [((a >> sh) & 0xFF, (b >> sh) & 0xFF) for a, b in s0]
        print(f"    byte{j}: " + " ".join(f"{x:02x}->{y:02x}" for x, y in pairs))
        diffs = {y ^ SBOX[x] for x, y in pairs}
        print(f"      out^sbox(in) distinct: {sorted(hex(d) for d in diffs)}")
