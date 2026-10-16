# Pin the exact pre-round composition from checkpoint transitions.
SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
 "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
 "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
 "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
 "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
 "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")


def xt(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = xt(a)
        b >>= 1
    return p


def mc_col(c):
    return bytes([
        gmul(c[0], 2) ^ gmul(c[1], 3) ^ c[2] ^ c[3],
        c[0] ^ gmul(c[1], 2) ^ gmul(c[2], 3) ^ c[3],
        c[0] ^ c[1] ^ gmul(c[2], 2) ^ gmul(c[3], 3),
        gmul(c[0], 3) ^ c[1] ^ c[2] ^ gmul(c[3], 2)])


def sb(s):
    return bytes(SBOX[b] for b in s)


def isr(s):
    o = list(s)
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4):
            o[4 * c + r] = row[c]
    return bytes(o)


def sr(s):
    o = list(s)
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            o[4 * c + r] = row[c]
    return bytes(o)


def mc(s):
    return b"".join(mc_col(s[4 * i:4 * i + 4]) for i in range(4))


def xora(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


L = [bytes.fromhex(h) for h in [
 "3bc0d5e23cfe70af70bd705a3cd88c0d",
 "cad02ea35b93ca9e6f85b608f421dde1",
 "7470310a39dc740ba8974e30bffdc1f8",
 "1cfd27e51b5e29096d112a39b1f377be",
 "9c49712560cf4fac64afdc55698312f5",
 "67e43064c65d61a59bef5ab3dce4ce4c",
 "85b97844006d93b442e76ef0cd15abe3",
 "6456af1518ed1e6582cc9a90cbe2c755",
 "4343b4acdc6963794ff611e0dea8296e",
 "fea81f9be5673d4f752186af0eded21f",
]]
C = [bytes.fromhex(h) for h in (
    "f110fb41676dba311f38c652c8f951ec",
    "3db456c07b9166a509bef66cd870654b",
    "a15d4820c630f211d908344311f165af",
    "bf151bb9c4847d1ccd3a8b70154aee3b")]

# FACT: xora(mc(sr(L[2])), L[3]) == [3d,0...0]
print("f1:", xora(mc(sr(L[2])), L[3]).hex())
print("sb(L3)          :", sb(L[3]).hex())
print("L4              :", L[4].hex())
d = xora(L[3], L[4])
inv_d = bytes(SBOX.index(b) for b in L[4])  # sb preimages
pre = bytes()
# candidate: L4 = sb(L3 ^ K) -> K = invsb(L4) ^ L3
K = xora(bytes(SBOX.index(b) for b in L[4]), L[3])
print("K = invsb(L4)^L3:", K.hex())
# compare with C[1] variants
print("C[1]            :", C[1].hex())
print("K^C[1]          :", xora(K, C[1]).hex())
# also for round 3: K3 = invsb(L6) ^ L5 ; and L5 vs mc(sr(L4))^..
K3 = xora(bytes(SBOX.index(b) for b in L[6]), L[5])
print("K3=invsb(L6)^L5 :", K3.hex())
print("C[2]            :", C[2].hex())
print("f3: mc(sr(L4))^L5:", xora(mc(sr(L[4])), L[5]).hex())
# and the very first: K0 = invsb(L2)^L1
K0 = xora(bytes(SBOX.index(b) for b in L[2]), L[1])
print("K0=invsb(L2)^L1 :", K0.hex())
print("C[0]            :", C[0].hex())
# final: pre-round-4 -> pre-round-1 state:
K4 = xora(bytes(SBOX.index(b) for b in L[8]), L[7])
print("K4=invsb(L8)^L7 :", K4.hex())
print("C[3]            :", C[3].hex())
print("mc(sr(L6))^L7   :", xora(mc(sr(L[6])), L[7]).hex())
print("L9 (pre-keyed)  :", L[9].hex())
print("mc(sr(L8))      :", mc(sr(L[8])).hex())
print("delta to L9     :", xora(mc(sr(L[8])), L[9]).hex())
