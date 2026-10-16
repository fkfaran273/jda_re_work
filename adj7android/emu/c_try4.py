# adj7 Android body SPN — corrected law, end-to-end verification.
SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
 "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
 "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
 "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
 "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
 "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
KEY = bytes.fromhex(
 "20ff2ce6100d3d3f18397e2ee95cd1cb254fb30fa132afc29bb9dfd7d157e47b"
 "57373fc8126f57a25f037cd9e30af8af6b8026f59fe7dc62510b56e0d509e7be"
 "1d00ea235a3ae8d4506cc158e6336c7806b334d8cc01bdefc85fbe5a48030c0a"
 "accb9c7ca3a421fda69db5f015fb8c7e0f5701f39603e9490b090246165f5b30"
 "cb60e1193d9195b1ce5975148ef7acfdb66d985b753b24472b677354686d7d57"
 "cc549d1ba4905dff3f9c7dbee43e84")
PRE = [bytes.fromhex(h) for h in (
    "f110fb41676dba311f38c652c8f951ec",
    "3db456c07b9166a509bef66cd870654b",
    "a15d4820c630f211d908344311f165af",
    "bf151bb9c4847d1ccd3a8b70154aee3b")]
IV0 = bytes.fromhex("40e0f7831ec4508f5085436f0de0bc39")
BODY = bytes.fromhex(
 "4da745a0be7da89170af6e32246cd7d6"
 "8a8930190438058b4ca1fabb7ce816c1"
 "b57ed3ec908d3f47de77c59d457fbc61"
 "f03f7a569b54c6bba4a0a803c52e50d2"
 "577b91c9afd302df0c9061d9b92acb23"
 "1ea2471b8bfa25fd69c0047ba3ca1659"
 "98fb620609d9aaf3e35ebe93cffa78c0"
 "14ae3aed588fd0d7a55d37408f7fda4f"
 "61393831a790ef0956756512a9c1e98c"
 "35f19b299a049a26c4327339ea033069"
 "c250bea222f3f27f06858658a616a7f7"
 "10fb9b9d63355d32b4d65ee5a3a87032"
 "bfc6374f9a9e2a91ecf28927892f5942"
 "bae4fa1b3e43294e8ffe0fb6fdf39d47"
 "57fea903485e028f845f014bdbb35520"
 "1d94b73f7ff50deac19dc402e0e645c6")


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


def block_crypt(x, tail="none"):
    s = bytes(x)
    for c in PRE:                       # 4 pre-rounds: ARK SB SR MC
        s = xor(s, c)
        s = mc(sr(sb(s)))
    s = bytes([s[0] ^ 0x75]) + s[1:]    # early ST[0] ^= KEY[0]^0x55
    # keyed round 1: ST[1..15] ^= KEY[0..14]^0x55
    k1 = bytes(b ^ 0x55 for b in KEY[:15])
    s = bytes([s[0]]) + xor(s[1:], k1)
    s = mc(sr(sb(s)))
    for r in range(2, 11):              # keyed rounds 2..10
        off = 15 + 16 * (r - 2)
        k = bytes(b ^ 0x55 for b in KEY[off:off + 16])
        s = xor(s, k)
        if r < 10:
            s = mc(sr(sb(s)))
        else:
            s = sr(sb(s))               # round 10: no MC
    k11 = bytes(b ^ 0x55 for b in KEY[159:174])
    # round 11: slots 159..174 (15 bytes) -> ST[1..15]
    s = bytes([s[0]]) + xor(s[1:], k11)
    if tail == "sb":
        s = sb(s)
    elif tail == "sr":
        s = sr(s)
    elif tail == "sb_sr":
        s = sr(sb(s))
    return s


# traced block-0 init state (record0 ^ IV0):
init0 = bytes.fromhex("3bc0d5e23cfe70af70bd705a3cd88c0d")
for tail in ("none", "sb", "sr", "sb_sr"):
    got = block_crypt(init0, tail)
    print("tail=%-6s %s %s" % (tail, got.hex(),
          "MATCH" if got == BODY[:16] else ""))
