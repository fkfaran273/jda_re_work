# Stage-by-stage: simulate from L0, compare to every traced checkpoint.
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
        c[0] ^ gmul(c[1] ^ gmul(c[2], 2) ^ c[3], 1) if False else
        c[0] ^ c[1] ^ gmul(c[2], 2) ^ gmul(c[3], 3),
        gmul(c[0], 3) ^ c[1] ^ c[2] ^ gmul(c[3], 2)][0:4])


def sb(s):
    return bytes(SBOX[b] for b in s)


def sr(s):
    o = list(s)
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            o[4 * c + r] = row[c]
    return bytes(o)


def mc(s):
    return b"".join(bytes(mc_col(s[4 * i:4 * i + 4])) for i in range(4))


def xora(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


L = [bytes.fromhex(h) for h in [
 "3bc0d5e23cfe70af70bd705a3cd88c0d",   # 0 init = rec0^IV
 "cad02ea35b93ca9e6f85b608f421dde1",   # 1 ARK c1
 "7470310a39dc740ba8974e30bffdc1f8",   # 2 SB
 "1cfd27e51b5e29096d112a39b1f377be",   # 3 ARK c2 (post SR+MC of 2)
 "9c49712560cf4fac64afdc55698312f5",   # 4 SB
 "67e43064c65d61a59bef5ab3dce4ce4c",   # 5 ARK c3
 "85b97844006d93b442e76ef0cd15abe3",   # 6 SB
 "6456af1518ed1e6582cc9a90cbe2c755",   # 7 ARK c4
 "4343b4acdc6963794ff611e0dea8296e",   # 8 SB
 "fea81f9be5673d4f752186af0eded21f",   # 9 pre-round1 state (=post c4 rnd)
]]
PRE = [bytes.fromhex(h) for h in (
    "f110fb41676dba311f38c652c8f951ec",
    "3db456c07b9166a509bef66cd870654b",
    "a15d4820c630f211d908344311f165af",
    "bf151bb9c4847d1ccd3a8b70154aee3b")]

print("check ARK1:", xora(L[0], PRE[0]).hex(), "vs L1", L[1].hex(),
      xora(L[0], PRE[0]) == L[1])
print("check SB1:", sb(L[1]).hex(), "vs L2", L[2].hex(), sb(L[1]) == L[2])
t = mc(sr(L[2]))
print("mc(sr(L2)):", t.hex())
print("xor vs L3 :", xora(t, L[3]).hex(), "(should be PRE[1] if unrotated)")
# rotated check: L3[i] = t[i] ^ PRE[1][(i-1)%16]
rot = bytes(t[i] ^ PRE[1][(i - 1) % 16] for i in range(16))
print("rot-ARK   :", rot.hex(), rot == L[3])
