# Offline: try AES-128-family decryption of the FF body with the 176-B
# schedule (bytes 0..175 of the 0x900e3e8 block; 174/175 possibly corrupted).
# Score by printable/structured plaintext; cross-check 0011 body.
import itertools

SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
 "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
 "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
 "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
 "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
 "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
INV = [0]*256
for i, v in enumerate(SBOX):
    INV[v] = i

FF_BODY = bytes.fromhex(
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
N11_BODY = bytes.fromhex(
 "de7b11fa86ef2207175efda9b30eb87cdabad50e135f33e0")  # only C0 known-solid
IV = bytes.fromhex("40e0f7831ec4508f5085436f0de0bc39")

KEY175 = bytes.fromhex(
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
 "cc549d1ba4905dff3f9c7dbee43e84")   # 175 real bytes (0..174)
assert len(KEY175) == 175


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


def mc(col):
    return bytes(
        gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3],
        col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3],
        col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3),
        gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2))


def imc(col):
    return bytes([
        gmul(col[0], 14) ^ gmul(col[1], 11) ^ gmul(col[2], 13) ^ gmul(col[3], 9),
        gmul(col[0], 9) ^ gmul(col[1], 14) ^ gmul(col[2], 11) ^ gmul(col[3], 13),
        gmul(col[0], 13) ^ gmul(col[1], 9) ^ gmul(col[2], 14) ^ gmul(col[3], 11),
        gmul(col[0], 11) ^ gmul(col[1], 13) ^ gmul(col[2], 9) ^ gmul(col[3], 14)])


def sr(s, transpose=False):
    o = bytearray(16)
    for c in range(4):
        for r in range(4):
            if transpose:
                o[c*4+r] = s[r*4+c]
            else:
                o[c*4+r] = s[((c+r) % 4)*4+r]
    return bytes(o)


def isr(s, transpose=False):
    o = bytearray(16)
    for c in range(4):
        for r in range(4):
            if transpose:
                o[r*4+c] = s[c*4+r]
            else:
                o[((c+r) % 4)*4+r] = s[c*4+r]
    return bytes(o)


def mix(s):
    return b"".join(mc(s[i:i+4]) for i in (0, 4, 8, 12))


def imix(s):
    return b"".join(imc(s[i:i+4]) for i in (0, 4, 8, 12))


def sub(s, box):
    return bytes(box[b] for b in s)


def ark(s, k):
    return bytes(a ^ b for a, b in zip(s, k))


def aes128_dec(ct, keys, nosub_final_enc=False, transpose=False):
    # keys: list of 11 16B round keys in encrypt order k0..k10
    s = ark(ct, keys[10])
    if not nosub_final_enc:
        s = isr(s, transpose)
        s = sub(s, INV)
    else:
        s = isr(s, transpose)
    for r in range(9, 0, -1):
        s = ark(s, keys[r])
        s = imix(s)
        s = isr(s, transpose)
        s = sub(s, INV)
    return ark(s, keys[0])


def decrypt_body(body, keys, **kw):
    out = bytearray()
    prev = IV
    for i in range(0, len(body), 16):
        d = aes128_dec(body[i:i+16], keys, **kw)
        out += ark(d, prev)
        prev = body[i:i+16]
    return bytes(out)


def score(pt):
    pr = sum(1 for c in pt if 32 <= c < 127 or c in (0, 9, 10))
    return pr / len(pt)


best = []
for lastb in range(256):
    KEY176 = KEY175 + bytes([lastb])
    keys = [KEY176[i*16:(i+1)*16] for i in range(11)]
    for nosub in (False, True):
        for transpose in (False, True):
            for kord, kname in ((keys, "fwd"), (keys[::-1], "rev")):
                pt = decrypt_body(FF_BODY, kord, nosub_final_enc=nosub,
                                  transpose=transpose)
                sc = score(pt)
                best.append((sc, lastb, nosub, transpose, kname, pt))
best.sort(key=lambda t: -t[0])
for sc, lastb, nosub, transpose, kname, pt in best[:6]:
    print("score=%.3f last175=%02x nosub=%d transpose=%d key=%s" %
          (sc, lastb, nosub, transpose, kname))
    print("   ", pt[:80])
