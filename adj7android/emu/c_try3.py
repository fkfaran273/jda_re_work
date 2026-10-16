# Corrected uniform cipher law, end-to-end verify on traced blocks 0 & 1.
import gzip

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
C0t = bytes.fromhex("4da745a0be7da89170af6e32246cd7d6")
C1t = bytes.fromhex("8a8930190438058b4ca1fabb7ce816c1")


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


KSTREAM = b"".join(PRE) + bytes(b ^ 0x55 for b in KEY)
assert len(KSTREAM) == 239


def ark_rot(s, base, n):
    o = bytearray(s)
    for i in range(n):
        j = base + i
        o[(j + 1) % 16] ^= KSTREAM[j]
    return bytes(o)


def block_crypt(x):
    s = bytes(x)
    for r in range(1, 16):
        base = 16 * (r - 1)
        n = 16 if r < 15 else 15
        s = ark_rot(s, base, n)
        if r <= 13:
            s = mc(sr(sb(s)))
        elif r == 14:
            s = sr(sb(s))
    return s


# ---- traced init states ----
STLO = 0x900e6e8
stw = []
evi = 0
with gzip.open("trace4.txt.gz", "rt") as f:
    for line in f:
        p = line.split()
        if p[0] == "W":
            a = int(p[2], 16)
            if int(p[3]) == 4 and STLO <= a < STLO + 1024:
                stw.append(((a - STLO) // 4, int(p[4], 16) & 0xFF))
        evi += 1


def first_writes(base):
    seen = {}
    for idx, v in stw:
        if base <= idx < base + 16 and (idx - base) not in seen:
            seen[idx - base] = v
        if len(seen) == 16:
            break
    return bytes(seen[i] for i in range(16))


w0 = first_writes(0)
w1 = first_writes(16)
rec0 = bytes(a ^ b for a, b in zip(w0, IV0))
print("init0 :", w0.hex())
print("rec0  :", rec0)
print("init1 :", w1.hex())
# what IV produced init1? assume record[16:32] known from template? unknown
# a-field; instead test chain: init1 ^ C0 = rec1?
rec1_guess = bytes(a ^ b for a, b in zip(w1, C0t))
print("init1^C0:", rec1_guess)

got0 = block_crypt(w0)
print("crypt(init0) =", got0.hex(), "target", C0t.hex(),
      "MATCH" if got0 == C0t else "FAIL")
