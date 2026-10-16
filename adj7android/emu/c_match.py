# Match op-order for pre-rounds and ARK rounds against traced layers.
import gzip, itertools

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


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# traced layers (from c_stagewise output) for block 0
LAYERS = [
 "3bc0d5e23cfe70af70bd705a3cd88c0d",
 "cad02ea35b93ca9e6f85b608f421dde1",
 "7470310a39dc740ba8974e30bffdc1f8",
 # layer3 partial (SR+MC fused) skipped
 "1cfd27e51b5e29096d112a39b1f377be",
 "9c49712560cf4fac64afdc55698312f5",
 # layer6/7 partial
 "67e43064c65d61a59bef5ab3dce4ce4c",
 "85b97844006d93b442e76ef0cd15abe3",
 # partials
 "6456af1518ed1e6582cc9a90cbe2c755",
 "4343b4acdc6963794ff611e0dea8296e",
 # partials
 "fea81f9be5673d4f752186af0eded21f",   # pre-round-1 state (round phase)
]
L = [bytes.fromhex(h) for h in LAYERS]

PREK = [bytes.fromhex(h) for h in (
    "f110fb41676dba311f38c652c8f951ec",
    "3db456c07b9166a509bef66cd870654b",
    "a15d4820c630f211d908344311f165af",
    "bf151bb9c4847d1ccd3a8b70154aee3b")]

# layer pattern per pre-round: [ARK(16), SB(16), partial(15), partial(13)]
# full checkpoints (16-wide layers) only:
#   idx0: init
#   idx1: ARK(c1)   idx2: SB
#   idx4: ARK(c2)   idx5: SB
#   idx7: ARK(c3)?? wait idx7 below maps differently; recompute with the
#   actual list above: L[0]=init L[1]=ARKc1 L[2]=SB
#                     L[3]=ARKc2 L[4]=SB
#                     L[5]=ARKc3 L[6]=SB
#                     L[7]=ARKc4 L[8]=SB
#                     L[9]=pre-round-1 state
for i in range(len(L)):
    print(i, L[i].hex())
print()
# check ARK deltas
for j, c in zip((1, 3, 5, 7), PREK):
    d = xor(L[j - 1], L[j])
    print("delta before L%d vs PREK:" % j, d.hex(), "== ", d == c)

# Now find transform T with T(SB(ARK(c_i)(prev))) = ARK(c_{i+1})(prev)
# i.e. T(L2) ^ c2 = L3 -> T(L2) = L3 ^ c2
tgt = xor(L[3], PREK[1])
print("\ntarget T(L2):", tgt.hex())
cands = {
    "MC(SR(x))": mc(sr(L[2])),
    "SR(MC(x))": sr(mc(L[2])),
    "MC(x)": mc(L[2]),
    "SR(x)": sr(L[2]),
    "MC(SR(SB(x)))": mc(sr(sb(L[2]))),
    "MC(SB(SR(x)))": mc(sb(sr(L[2]))),
    "SB(MC(SR(x)))": sb(mc(sr(L[2]))),
    "SR(SB(MC(x)))": sr(sb(mc(L[2]))),
    "MC(MC(SR(x)))": mc(mc(sr(L[2]))),
}
for n, v in cands.items():
    print("%-16s %s %s" % (n, v.hex(), "MATCH" if v == tgt else ""))
