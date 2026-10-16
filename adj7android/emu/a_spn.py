# SPN law search: known (in,out) pair + 12x16B key block; try AES-family
# variants (sbox std/custom, SR std/transpose, MC/no-MC final, round orders).
import struct, itertools

IV = bytes.fromhex("40e0f7831ec4508f5085436f0de0bc39")
C0 = bytes.fromhex("4da745a0be7da89170af6e32246cd7d6")
P0 = b'{ "a":  1844'          # record[0:16] with A = 20-digit max u64
SPN_IN = bytes(a ^ b for a, b in zip(P0, IV))

KEYS_RAW = bytes.fromhex(
 "20ff2ce6100d3d3f18397e2ee95cd1cb"
 "254fb30fa132afc29bb9dfd7d157e47b"
 "57373fc8126f57a25f037cd9e30af8af"
 "6b8026f59fe7dc62510b56e0d509e7be"
 "1d00ea235a3ae8d4506cc158e6336c78"
 "06b334d8cc01bdefc85fbe5a48030c0a"
 "accb9c7ca3a421fda69db5f015fb8c7e"
 "0f5701f39603e9490b090246165f5b30"
 "cb60e1193d9195b1ce5975148ef7acfd"
 "b66d985b753b24472b677354686d7d57"
 "cc549d1ba4905dff3f9c7dbee43e8450"
 "ad67123b56962e3521c6583e698fc30")
K = [KEYS_RAW[i*16:(i+1)*16] for i in range(12)]

SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
 "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
 "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
 "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
 "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
 "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p

def sr_std(s):      # row r rotated left by r (column-major state s[4c+r])
    o = [0]*16
    for c in range(4):
        for r in range(4):
            o[4*c + r] = s[4*((c + r) % 4) + r]
    return o

def sr_tp(s):       # M[r][c] = M[(r+c)%4][c]  (rows shifted down)
    o = [0]*16
    for c in range(4):
        for r in range(4):
            o[4*c + r] = s[4*c + ((r + c) % 4)]
    return o

def mc_std(s):
    o = [0]*16
    for c in range(4):
        col = s[4*c:4*c+4]
        o[4*c+0] = gmul(col[0],2) ^ gmul(col[1],3) ^ col[2] ^ col[3]
        o[4*c+1] = col[0] ^ gmul(col[1],2) ^ gmul(col[2],3) ^ col[3]
        o[4*c+2] = col[0] ^ col[1] ^ gmul(col[2],2) ^ gmul(col[3],3)
        o[4*c+3] = gmul(col[0],3) ^ col[1] ^ col[2] ^ gmul(col[3],2)
    return o

def xor16(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def spn(inp, rounds, sbox, srf, mc_final, sb_final=True, mc_first=False):
    s = list(xor16(inp, K[0]))
    for r in range(1, rounds):
        s = [sbox[b] for b in s]
        s = srf(s)
        s = mc_std(s)
        s = list(xor16(bytes(s), K[r]))
    # final round
    if sb_final:
        s = [sbox[b] for b in s]
    s = srf(s)
    s = list(xor16(bytes(s), K[rounds-1]))
    return bytes(s)

hits = []
for rounds in (11, 12):
    for sb_final in (True, False):
        for srf, sname in ((sr_std, "std"), (sr_tp, "tp")):
            for sbox, sbname in ((SBOX, "aes"),):
                out = spn(SPN_IN, rounds, sbox, srf, None, sb_final)
                tag = "r=%d sbf=%s sr=%s sb=%s" % (rounds, sb_final, sname, sbname)
                if out == C0:
                    print("MATCH", tag)
                    hits.append(tag)
                else:
                    d = sum(1 for a, b in zip(out, C0) if a == b)
                    print("no  ", tag, "eq bytes", d)
print("hits:", hits)
