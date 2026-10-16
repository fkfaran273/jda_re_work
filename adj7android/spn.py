# adj7 Android 3.62.0 body cipher — THE LAW (trace-verified 11 stages + final)
#
# chunk: s = record_chunk ^ IV_or_prev_cipher   (per-byte lanes)
#   4 pre-rounds:  s = MC(SR(SB(s ^ PRE[i])))
#   tweak:         s[0] ^= 0x75
#   round 1:       s[1:16] ^= KEY[0:15] ^ 0x55 ; s = MC(SR(SB(s)))
#   rounds 2..9:   s ^= KEY[15+16(r-2):16] ^ 0x55 ; s = MC(SR(SB(s)))
#   round 10:      s ^= KEY[143:159] ^ 0x55 ; s = SR(SB(s))          (no MC)
#   final:         s ^= KEY[159:175] ^ 0x55                          -> cipher
# CBC: chunk0 IV = header(16); chunk k IV = cipher[k-1].
import struct, hmac, hashlib

SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
 "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
 "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
 "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
 "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
 "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
ISBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    ISBOX[_v] = _i

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
TAG_K = bytes.fromhex(
    "2A4CC07960D647623CC386DCEFAFBF25B669914D32CC8585A1ED7F920EF591EB")

def _xt(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xt(a)
        b >>= 1
    return p

def _mc_col(c):
    return bytes([
        gmul(c[0], 2) ^ gmul(c[1], 3) ^ c[2] ^ c[3],
        c[0] ^ gmul(c[1], 2) ^ gmul(c[2], 3) ^ c[3],
        c[0] ^ c[1] ^ gmul(c[2], 2) ^ gmul(c[3], 3),
        gmul(c[0], 3) ^ c[1] ^ c[2] ^ gmul(c[3], 2)])

def sb(s):
    return bytes(SBOX[b] for b in s)

def isb(s):
    return bytes(ISBOX[b] for b in s)

def sr(s):
    o = list(s)
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            o[4 * c + r] = row[c]
    return bytes(o)

def isr(s):
    o = list(s)
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4):
            o[4 * c + r] = row[c]
    return bytes(o)

def mc(s):
    return b"".join(_mc_col(s[4 * i:4 * i + 4]) for i in range(4))

def imc_col(c):
    # inverse of the [2 3 1 1] circulant
    return bytes([
        gmul(c[0], 14) ^ gmul(c[1], 11) ^ gmul(c[2], 13) ^ gmul(c[3], 9),
        gmul(c[0], 9) ^ gmul(c[1], 14) ^ gmul(c[2], 11) ^ gmul(c[3], 13),
        gmul(c[0], 13) ^ gmul(c[1], 9) ^ gmul(c[2], 14) ^ gmul(c[3], 11),
        gmul(c[0], 11) ^ gmul(c[1], 13) ^ gmul(c[2], 9) ^ gmul(c[3], 14)])

def imc(s):
    return b"".join(imc_col(s[4 * i:4 * i + 4]) for i in range(4))

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def chunk_encrypt(rec, iv):
    s = _xor(rec, iv)
    for c in PRE:
        s = mc(sr(sb(_xor(s, c))))
    s = bytes([s[0] ^ 0x75]) + s[1:]
    s = bytes([s[0]]) + _xor(s[1:], bytes(b ^ 0x55 for b in KEY[0:15]))
    s = mc(sr(sb(s)))
    for r in range(2, 10):
        off = 15 + 16 * (r - 2)
        s = _xor(s, bytes(b ^ 0x55 for b in KEY[off:off + 16]))
        s = mc(sr(sb(s)))
    s = _xor(s, bytes(b ^ 0x55 for b in KEY[143:159]))
    s = sr(sb(s))
    return _xor(s, bytes(b ^ 0x55 for b in KEY[159:175]))

def chunk_decrypt(ct, iv):
    s = _xor(ct, bytes(b ^ 0x55 for b in KEY[159:175]))
    s = isb(isr(s))
    s = _xor(s, bytes(b ^ 0x55 for b in KEY[143:159]))
    for r in range(9, 1, -1):
        off = 15 + 16 * (r - 2)
        s = isb(isr(imc(s)))
        s = _xor(s, bytes(b ^ 0x55 for b in KEY[off:off + 16]))
    s = isb(isr(imc(s)))
    s = bytes([s[0]]) + _xor(s[1:], bytes(b ^ 0x55 for b in KEY[0:15]))
    s = bytes([s[0] ^ 0x75]) + s[1:]
    for c in reversed(PRE):
        s = isb(isr(imc(s)))
        s = _xor(s, c)
    return _xor(s, iv)

def body_encrypt(record, header):
    out, prev = b"", header
    for k in range(16):
        c = chunk_encrypt(record[16 * k:16 * k + 16], prev)
        out += c
        prev = c
    return out

def body_decrypt(body, header):
    rec, prev = b"", header
    for k in range(16):
        c = body[16 * k:16 * k + 16]
        rec += chunk_decrypt(c, prev)
        prev = c
    return rec

def make_tag(body):
    return hmac.new(TAG_K, body, hashlib.sha256).digest()

if __name__ == "__main__":
    # self-proof vs the FF-nonce emu mint (record chunk0 known from trace)
    IV = bytes.fromhex("40e0f7831ec4508f5085436f0de0bc39")
    R10 = bytes.fromhex("4f3e4468f08c6d99dac5a71acfddbc07")
    C0 = bytes.fromhex("4da745a0be7da89170af6e32246cd7d6")
    init = bytes.fromhex("3bc0d5e23cfe70af70bd705a3cd88c0d")
    # forward from init through the law must equal C0
    s = init
    for c in PRE:
        s = mc(sr(sb(_xor(s, c))))
    s = bytes([s[0] ^ 0x75]) + s[1:]
    s = bytes([s[0]]) + _xor(s[1:], bytes(b ^ 0x55 for b in KEY[0:15]))
    s = mc(sr(sb(s)))
    for r in range(2, 10):
        off = 15 + 16 * (r - 2)
        s = _xor(s, bytes(b ^ 0x55 for b in KEY[off:off + 16]))
        s = mc(sr(sb(s)))
    s = _xor(s, bytes(b ^ 0x55 for b in KEY[143:159]))
    s = sr(sb(s))
    c0 = _xor(s, bytes(b ^ 0x55 for b in KEY[159:175]))
    print("forward C0 match:", c0 == C0)
    # roundtrip
    print("roundtrip:", chunk_decrypt(C0, IV) == init)
