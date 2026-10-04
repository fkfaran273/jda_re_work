"""adj9_signer.py — the adj9 signature algorithm in closed form.

One stdlib-only file.  One signing ~3 ms, byte-exact against genuine device
captures (--selftest).

    blob(192) = header(16) || whiten(record(144), header) || digest(32)

  header   bionic srand(second): MINSTD rand, 310 warm-up draws, then 8
           draws XORed in pairs, big-endian.
  region   seed S -> d0/d2/d4: shuffle + bit-transpose; d0 = selector
           halfwords (head phase + the 0x40|(i&7) cycle); d2 = BE32(S).
  record   01 00 08 | head16 | 02 | BE32(S) | 03 | D9 | 04 | BLOCK |
           05 | sha256("") | 06 01 07 | 00*14 | 0000 | 0e*14
  BLOCK    SHA-256 (standard padding and constants, custom IV2) over
           D9 || 00 08 || head16 || LE32(S) || sha256("") || 01 || 00*16
           || claims(unpadded).
  whiten   14-round SPN, CBC-chained from the header: S-box = the AES
           S-box (generated), round keys KB, PI = 4x4 rows rotated right
           by row index (generated), F = AES-xtime byte-circulant
           (generated).
  digest   sha256((K^opad) || opad || sha256((K^ipad) || ipad || body))
           — pads hashed twice, NOT standard HMAC.
  claims   one presence-filtered law for SDK 5.7.0 and 5.8.0: sorted
           profile keys + pinned '1500000' + sorted tail + block2.

Stored values: only the cipher's three secrets (KB, IV2, K) — see PART 0.
Everything else is computed from logic.  App differences = campaign_data.json
(cert_sha1 is the only per-app secret).

LAYOUT:  PART 0 constants · PART 1 header · PART 2 region · PART 3 claims
         PART 4 block hash · PART 5 whitening · PART 6 digest · PART 7 signer
         PART 8 one-click API · PART 9 self-test

USE (the funnel calls exactly this):

    import adj9_signer as sg
    sg.configure(campaign_data)                    # once per app
    blob, second, info = sg.sign(params, kind)     # session|click|attribution
    auth = sg.auth_header(blob)

    python adj9_signer.py --selftest   # self-contained: 9 genuine captures inside
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
import time

# =======================================================================
# PART 0 — CONSTANTS: every value in one place
#   0a. shared math — derived from two choices (the modulus 2^31-1 and
#       the MINSTD multiplier 7**5)
#   0b. KEY MATERIAL — the cipher's three secrets, their actual values.
#       (Inside the native they live as instruction immediates — KB and
#       IV2 additionally XOR-obfuscated — and are re-extractable from the
#       program image: kb_derive/derive_kb.py 240/240,
#       iv2k_derive/hunt_iv2k.py 32/32 + 32/32.)
#   0c. head phases — device-state selector literals (the server cannot
#       verify the choice; proven live)
# =======================================================================

# 0a. shared math
_MINSTD_M = (1 << 31) - 1                # the Mersenne prime 2^31 - 1
_MINSTD_A = 7 ** 5                       # 16807, the MINSTD multiplier
_MINSTD_Q = _MINSTD_M // _MINSTD_A       # Schrage q  (127773)
_MINSTD_R = _MINSTD_M % _MINSTD_A        # Schrage r  (2836)
_MASK16 = (1 << 16) - 1                  # halfword mask (d0 selectors)
_MASK32 = (1 << 32) - 1                  # word mask
_ZERO_STATE_SEED = 123459876             # the native's zero-state default

# 0b. key material
KB_HEX = ("16a963dd519db84e42b09da356557a13cbda29f7e7246b5dd96a4d671b4e9651"
          "3839b27269a40a3c2b14979f7d41ed8c34597c93d37d17ce0a175aa91159ccf8"
          "f172f3f098d6f9ccb3c26e53ce8383dfbfb5900d6cc887c366dfdd6a77861192"
          "b1f0bc05292645c99ae42b9a5467a8459f305263f3f8d5a0952708cae2a11958"
          "8b24d69da202935438e6b8ce6c81108bcf3c985e3cc44dfea9e345344b425c6c"
          "b76e862e156c157a2d8aadb4410bbd3f4c17e22b70d3afd5d930eae19272b68d"
          "d720db61c24cce1befc663afaecdde90a8aaff4bd879509e0149ba7f933b0cf2"
          "75de52bdb7929ca65854ff09f6992199")
KB = bytes.fromhex(KB_HEX)          # 15 x 16-B round keys; KB[224:240] is
                                    # the final sweep key
IV2 = bytes.fromhex("eba2c4350f4002dc9fa8dac5127035ba"
                    "7a30ed9323473054bbe3cd00f1355ea5")  # block-hash IV
DK = bytes.fromhex("690f60944dddd9847db55cd7d2d576b3"
                   "0451723fbcfa92df62b55f6fec60f2de")  # digest MAC key

# 0c. head phases
HEAD_FIRST = (43,)    # selector literal: the pool's first entry


# =======================================================================
# PART 1 — HEADER: bionic rand (MINSTD), pair-XORed
# =======================================================================
class Random3:
    """bionic's rand(): a 31-word additive-feedback LCG with the classic
    310-draw warm-up and a Schrage multiply over the shared MINSTD block."""

    __slots__ = ("r", "f", "b")

    def __init__(self, seed):
        r = self.r = [0] * 31
        s = seed & _MASK32
        if s == 0:
            s = 1
        w = s if s < 2 ** 31 else s - 2 ** 32
        r[0] = w
        prev = w
        for i in range(1, 31):
            if prev >= 0:
                hi = prev // _MINSTD_Q
                lo = prev - hi * _MINSTD_Q
            else:
                hi = -((-prev) // _MINSTD_Q)
                lo = prev - hi * _MINSTD_Q
            word = _MINSTD_A * lo - _MINSTD_R * hi
            if word < 0:
                word += _MINSTD_M
            prev = word
            r[i] = word
        self.f = 3
        self.b = 0
        for _ in range(310):
            self.next()

    def next(self):
        v = (self.r[self.f] + self.r[self.b]) & _MASK32
        self.r[self.f] = v if v < 2 ** 31 else v - 2 ** 32
        o = v >> 1
        self.f = (self.f + 1) % 31
        self.b = (self.b + 1) % 31
        return o


def make_header(unix_sec):
    """The 16-byte blob header (and the whitening IV) for a signing second."""
    R = Random3(unix_sec)
    d = [R.next() for _ in range(8)]
    w = [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return b"".join(struct.pack(">I", x) for x in w)


# =======================================================================
# PART 2 — REGION: seed S -> d0 / d2 / d4
# =======================================================================
def _step(x):
    """One MINSTD Schrage step of the region PRNG (same generator as
    bionic's rand above): x = (x mod Q)*A - (x div Q)*R."""
    if x == 0:
        x = _ZERO_STATE_SEED
    hi, lo = divmod(x, _MINSTD_Q)
    y = lo * _MINSTD_A - hi * _MINSTD_R
    if y < 0:
        y += _MINSTD_M
    return y & _MINSTD_M


def _raw16(seed):
    """Shuffle + pair consumption -> 16 halfwords."""
    state = seed & _MASK32
    perm = [0] * 16
    for i in range(16):
        r = _step(state)
        state = r
        j = r % (i + 1)
        perm[i], perm[j] = perm[j], i
    pre = []
    for i in range(16):
        if (i & 1) == 0:
            state = _step(state)
        r = state
        v = (r >> 16) & _MASK16 if (i & 1) == 0 else r
        pos = 15 - perm[i]
        pre.append(((v & ((1 << pos) - 1)) | (1 << pos)) & _MASK16)
    return pre


def _transpose16(pre):
    out = [0] * 16
    for j in range(16):
        v = 0
        for i in range(16):
            if pre[i] & (1 << (15 - j)):
                v |= 1 << (15 - i)
        out[j] = v
    return out


def _d4_words(seed):
    """Descriptor #4: 8 big-endian words from the little-endian halfword
    stream."""
    raw = _transpose16(_raw16(seed))
    packed = b"".join(x.to_bytes(2, "little") for x in raw)
    return [int.from_bytes(packed[i:i + 4], "big") for i in range(0, 32, 4)]


def _d0_source(d4):
    """The eight d4 halfwords consumed by the d0 source-word selector."""
    d4_bytes = b"".join(word.to_bytes(4, "big") for word in d4)
    return [int.from_bytes(d4_bytes[i:i + 2], "little")
            for i in range(16, 32, 2)]


def _selector_halfword(mask, source):
    value = 0
    for bit in range(8):
        if (mask >> bit) & 1:
            value ^= source[7 - bit]
    return value & _MASK16


def _d0_words(d4, head=None):
    """Descriptor #0: 36 big-endian words = the head selector phase followed
    by the stable 0x40|(i&7) cycle, each selector expanded into one
    halfword."""
    source = _d0_source(d4)
    prefix = HEAD_FIRST if head is None else tuple(head)
    selectors = tuple(prefix[i] if i < len(prefix) else (0x40 | (i & 7))
                      for i in range(72))
    values = [_selector_halfword((s << 1) + 3, source) for s in selectors]
    raw = b"".join(v.to_bytes(2, "little") for v in values)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 144, 4)]


def region(V, pid=0, tid=0, head=None):
    """(d0, d2, d4) descriptor words for a fill instant.  V is the 32-bit
    seed."""
    del tid
    seed = ((V & _MASK32) ^ ((pid & _MASK16) << 16)) & _MASK32
    d4 = _d4_words(seed)
    d0 = _d0_words(d4, head=head)
    d2 = int.from_bytes(seed.to_bytes(4, "little"), "big")
    return d0, d2, d4


def head_words(d0w):
    """d0[0..3] -> record[3:19): each 32-bit word 16-bit-swapped, LE-packed."""
    return b"".join(struct.pack("<I", ((w & 0xFFFF) << 16) | (w >> 16))
                    for w in d0w[:4])


def head16_for(S, head=None):
    """The 16-byte d0 head the record carries for seed S and a selector
    phase."""
    return head_words(_d0_words(_d4_words(S), head=head))


# =======================================================================
# PART 3 — CLAIMS: the ONE generic, presence-filtered descriptor-#10 law.
# The union of the proven 5.7.0 (penti) and 5.8.0 (creditsea) key lists; a
# key enters only when the caller's map actually carries it non-empty, so
# the single law reproduces BOTH SDK versions byte-exactly.
# =======================================================================
PROFILE = [
    'adj_verification', 'android_uuid', 'api_level', 'app_token', 'app_version',
    'country', 'created_at', 'device_name', 'device_type', 'environment',
    'gps_adid', 'gps_adid_src', 'hardware_name', 'installed_at', 'os_build',
    'os_name', 'os_version', 'package_name',
    # 5.7.0-only optional claim: enters only when the map carries it.
    'push_token',
]
SESSION_EXTRA = ['initiating_package_name']
CLICK_EXTRA = ['click_time', 'click_time_server', 'google_play_instant',
               'install_begin_time', 'install_begin_time_server',
               'install_version', 'referrer', 'referrer_api']
ATTR_DROP = ['hardware_name', 'installed_at', 'os_build']
ATTR_EXTRA = ['initiated_by']
SESSION_TAIL = ['session_count', 'session_length', 'store_name_from_system',
                'subsession_count', 'time_spent', 'tracking_enabled',
                'updated_at']
CLICK_TAIL = ['session_count', 'session_length', 'source', 'subsession_count',
              'time_spent', 'tracking_enabled', 'updated_at']
ATTR_TAIL = ['tracking_enabled']
BLOCK2 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']
PINNED = 'adj_signing_id'
ADJ_SIGNING_ID = '1500000'


def desc10_keys(val, kind):
    """Emission key order for one activity kind (law keys present in val)."""
    if kind == 'session':
        profile, tail = PROFILE + SESSION_EXTRA, SESSION_TAIL
    elif kind == 'click':
        profile, tail = PROFILE + CLICK_EXTRA, CLICK_TAIL
    elif kind == 'attribution':
        profile = [k for k in PROFILE if k not in ATTR_DROP] + ATTR_EXTRA
        tail = ATTR_TAIL
    else:
        raise ValueError('adj9 claims law known for kinds: session, click, '
                         'attribution (got %r)' % (kind,))
    keys = [k for k in sorted(profile) if val.get(k)]
    keys.append(PINNED)                      # emitted pinned; read or not
    keys += [k for k in sorted(tail) if val.get(k)]
    keys += [k for k in BLOCK2 if val.get(k)]
    return keys


def build_claims(val, kind, signing_id=None):
    """val: dict key->str.  Returns the UNPADDED descriptor-#10 byte string."""
    keys = desc10_keys(val, kind)
    parts = []
    for k in keys:
        v = val.get(k)
        if k == PINNED and not v:
            v = signing_id or ADJ_SIGNING_ID
        if not v:
            raise KeyError('adj9 claims law missing value for %r' % k)
        parts.append(v)
    return ''.join(parts).encode('latin1')


def claims_bytes(claims, kind=None, val=None):
    """Accept either a ready claims payload (bytes/str) or a claims map."""
    if isinstance(claims, (bytes, bytearray)):
        return bytes(claims)
    if isinstance(claims, str):
        return claims.encode('latin1')
    if val is None:
        val = claims
    return build_claims(val, kind or 'session')


# =======================================================================
# PART 4 — BLOCK: SHA-256 over the claims message, chained from the custom
# IV2 (standard padding; the round constants are generated from the
# FIPS 180-4 definition).
# =======================================================================
def _icbrt(n):
    """Integer cube root (Newton)."""
    if n == 0:
        return 0
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


def _derive_k256():
    """The standard SHA-256 round constants, generated from first principles:
    the first 32 bits of the fractional parts of the cube roots of the first
    64 primes (exact integer arithmetic: frac = icbrt(p << 96) mod 2^32)."""
    ks, n = [], 2
    while len(ks) < 64:
        if all(n % q for q in range(2, int(n ** 0.5) + 1)):
            ks.append(_icbrt(n << 96) & _MASK32)
        n += 1
    return ks


_K256 = _derive_k256()


def _compress(state, blk):
    w = list(blk)
    for i in range(16, 64):
        x = w[i - 15]
        s0 = (((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3)) \
            & _MASK32
        y = w[i - 2]
        s1 = (((y >> 17) | (y << 15)) ^ ((y >> 19) | (y << 13)) ^ (y >> 10)) \
            & _MASK32
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK32)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21))
              ^ ((e >> 25) | (e << 7))) & _MASK32
        t1 = (h + S1 + ((e & f) ^ (~e & g)) + _K256[i] + w[i]) & _MASK32
        S0 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19))
              ^ ((a >> 22) | (a << 10))) & _MASK32
        t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) & _MASK32
        h, g, f, e = g, f, e, (d + t1) & _MASK32
        d, c, b, a = c, b, a, (t1 + t2) & _MASK32
    return [(x + y) & _MASK32 for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def sha256_iv2(msg):
    """SHA-256 with the standard padding chained from the custom IV2.

    The compression itself is standard — verified byte-identical to
    hashlib.sha256 on 200 random inputs once the FIPS IV is injected — and
    the round constants are the standard ones.  It is hand-rolled only
    because hashlib exposes no way to chain from a custom IV."""
    st = list(struct.unpack(">8I", IV2))
    m = (msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64)
         + struct.pack(">Q", len(msg) * 8))
    for i in range(0, len(m), 64):
        blk = list(struct.unpack(">16I", m[i:i + 64]))
        st = _compress(st, blk)
    return struct.pack(">8I", *st)


SHA0 = hashlib.sha256(b"").digest()
BLOCK_TAIL = b"\x01" + b"\x00" * 16          # record[111] || record[114:130]


def block_message(S, head16, claims, d9):
    """D9 || 00 08 || head16 || LE32(S) || sha256("") || 17 B const ||
    claims."""
    return (bytes(d9) + b"\x00\x08" + bytes(head16)
            + struct.pack("<I", S & _MASK32) + SHA0 + BLOCK_TAIL
            + bytes(claims))


def predict_block(S, head16, claims, d9):
    """The 32-byte record[46:78) block."""
    return sha256_iv2(block_message(S, head16, claims, d9))


# =======================================================================
# PART 5 — WHITENING: the 14-round SPN, CBC-chained with the header.
#
# Structurally this IS AES-256 (verified): the S-box is the AES S-box, the
# mix is FIPS-197 MixColumns [2,3,1,1] over GF(2^8) mod 0x11B, 14 rounds
# with the last round's MIX skipped, 15 x 16-B round keys (the AES-256
# schedule size), CBC-chained from the header as IV.
#
# It is NOT standard AES, so a prebuilt AES module cannot produce these
# bytes — two deviations, both verified:
#   1. the permutation is the INVERSE ShiftRows direction (col - row, not
#      col + row; our PI is exactly inverse(AES ShiftRows));
#   2. the key schedule is custom — KB is not the FIPS-197 AES-256
#      expansion of any 32-B key (expanding KB[0:32] does not reproduce KB,
#      and the standard word recurrence fails).
# Hence the cipher is implemented here in raw form on purpose.
# =======================================================================
def _derive_tables():
    """SBOX and F_ROWS are GENERATED, not embedded:
    SBOX = the AES S-box — affine(inverse) in GF(2^8) mod the AES field
    polynomial;  F_ROWS = the byte-circulant whose sole independent
    generator is the xtime bit-matrix (A1 = A0 + I, A2 = A3 = I)."""
    # the AES field polynomial x^8 + x^4 + x^3 + x + 1, as its bit sum:
    _M = (1 << 8) | (1 << 4) | (1 << 3) | (1 << 1) | 1

    def _gmul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            b >>= 1
            a <<= 1
            if a & 0x100:
                a ^= _M
        return r

    def _ginv(a):
        r, b, e = 1, a, 254
        while e:
            if e & 1:
                r = _gmul(r, b)
            b = _gmul(b, b)
            e >>= 1
        return r

    def _rotl8(x, n):
        return ((x << n) | (x >> (8 - n))) & 0xFF

    _SBOX_BIAS = 0x63               # the AES affine additive constant
    sbox = []
    for v in range(256):
        iv = _ginv(v) if v else 0
        sbox.append(iv ^ _rotl8(iv, 1) ^ _rotl8(iv, 2) ^ _rotl8(iv, 3)
                    ^ _rotl8(iv, 4) ^ _SBOX_BIAS)

    _POLY_LOW = _M & 0xFF           # the field poly's low byte
    xt_rows = [(1 << ((j - 1) % 8)) | (((_POLY_LOW >> j) & 1) << 7)
               for j in range(8)]   # the xtime bit-matrix rows
    ident = [1 << j for j in range(8)]
    a1 = [xt_rows[j] ^ ident[j] for j in range(8)]
    fr = []
    for j in range(32):
        b, jj = j // 8, j % 8
        row = 0
        for d, blk in enumerate((xt_rows, a1, ident, ident)):
            row |= blk[jj] << (8 * ((b + d) % 4))
        fr.append(row)
    return bytes(sbox), fr


SBOX, F_ROWS = _derive_tables()


def _byte_tables(rows):
    """4 x 256-entry tables for a GF(2) 32x32 matrix given as 32 row masks.

    F(x)_j = parity(rows[j] & x), so the map is linear: tab[k][b] is the
    contribution of input byte k == b to the 32-bit output."""
    tab = []
    for k in range(4):
        t = [0] * 256
        for b in range(256):
            bits = b << (8 * k)
            v = 0
            for j in range(32):
                m = rows[j] & bits
                p = 0
                while m:
                    p ^= m & 1
                    m >>= 1
                if p:
                    v ^= 1 << j
            t[b] = v
        tab.append(t)
    return tab


_F_TAB = _byte_tables(F_ROWS)


def _apply_tab(tab, x):
    return (tab[0][x & 0xFF] ^ tab[1][(x >> 8) & 0xFF]
            ^ tab[2][(x >> 16) & 0xFF] ^ tab[3][(x >> 24) & 0xFF])


def _F(chunk):
    """The linear mix on a 16-B chunk: 4 little-endian words through F."""
    return b"".join(_apply_tab(_F_TAB,
                               int.from_bytes(chunk[4 * b:4 * b + 4],
                                              "little")).to_bytes(4, "little")
                    for b in range(4))


def _derive_pi():
    """The SHIFTROWS permutation: the 16-B chunk is a 4x4 matrix (index
    i = 4*col + row) and each row r is rotated right by r."""
    pi = [0] * 16
    for i in range(16):
        j, r = divmod(i, 4)
        pi[i] = 4 * ((j + (0, 3, 2, 1)[r]) % 4) + r
    return pi


_PI = _derive_pi()


def _pi1(chunk):
    """SHIFTROWS: out[_PI[i]] = in[i]."""
    out = bytearray(16)
    for i, c in enumerate(chunk):
        out[_PI[i]] = c
    return bytes(out)


_ROUND_KEYS = [KB[16 * r:16 * r + 16] for r in range(14)]   # 14 round keys
_FINAL_KEY = KB[224:240]                                   # final sweep key


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def whiten_chunk(chunk, wa):
    """One 16-B chunk through the SPN:  ADDROUNDKEY -> SBOX -> SHIFTROWS
    -> MIX, 14 rounds (MIX skipped on the last), then the final key."""
    x = _xor(chunk, wa)
    for r in range(14):
        x = _xor(x, _ROUND_KEYS[r])
        x = bytes(SBOX[v] for v in x)
        x = _pi1(x)
        if r < 13:
            x = _F(x)
    return _xor(x, _FINAL_KEY)


def whiten_forward(record, header):
    """record: 144 B plaintext, header: 16 B IV -> whitened body (144 B)."""
    out = bytearray()
    wa = header
    for k in range(9):
        c = whiten_chunk(record[16 * k:16 * k + 16], wa)
        out += c
        wa = c                      # CBC: each chunk chains to the next
    return bytes(out)


# =======================================================================
# PART 6 — DIGEST: the custom two-pass SHA-256 MAC over the whitened body
# =======================================================================
IPAD = b"\x36" * 32
OPAD = b"\x5c" * 32
K_IPAD = _xor(DK, IPAD)
K_OPAD = _xor(DK, OPAD)


def predict_digest(body):
    """body = blob[16:160) (144 B) -> digest = blob[160:192) (32 B).  The
    raw pad block is hashed a second time after the keyed block — NOT
    standard HMAC."""
    inner = hashlib.sha256(K_IPAD + IPAD + body).digest()
    return hashlib.sha256(K_OPAD + OPAD + inner).digest()


# =======================================================================
# PART 7 — SIGNER
# =======================================================================
def build_record(S, head16, claims, d9):
    """Assemble the 144-B record from its closed-form parts."""
    d9 = bytes(d9)
    head16 = bytes(head16)
    if len(head16) != 16:
        raise ValueError('head16 must be 16 bytes')
    if len(d9) != 20:
        raise ValueError('d9 (APK cert SHA-1) must be 20 bytes')
    block = predict_block(S, head16, claims, d9)
    out = bytearray(144)
    out[0:3] = b"\x01\x00\x08"
    out[3:19] = head16
    out[19] = 0x02
    out[20:24] = struct.pack(">I", S & _MASK32)   # d2: LE32(S) re-read BE
    out[24] = 0x03
    out[25:45] = d9
    out[45] = 0x04
    out[46:78] = block
    out[78] = 0x05
    out[79:111] = SHA0
    out[111:114] = b"\x06\x01\x07"
    out[114:128] = b"\x00" * 14
    out[128:130] = b"\x00\x00"
    out[130:144] = b"\x0e" * 14
    return bytes(out)


def sign_pure(second, S, claims, d9_hex, kind="session", head=HEAD_FIRST):
    """Mint the complete 192-byte adj9 signature.

    second : signing second (unix time) -> the 16-byte header
    S      : 32-bit fill seed -> d2/d4/d0 (region(S, 0, 0, head))
    claims : descriptor-#10 payload (bytes/str) OR a claims map (dict), which
             is then built with the presence-filtered law for `kind`
    d9_hex : the APK certificate SHA-1 as hex (PER-APP parameter)
    kind   : session | click | attribution (only used when claims is a map)
    head   : the d0 selector phase for this request
    """
    if isinstance(d9_hex, (bytes, bytearray)):
        d9 = bytes(d9_hex)
    else:
        d9 = bytes.fromhex(d9_hex)
    cb = claims_bytes(claims, kind=kind)
    head16 = head16_for(S, head)
    record = build_record(S, head16, cb, d9)
    header = make_header(second)
    body = whiten_forward(record, header)
    digest = predict_digest(body)
    return header + body + digest


# =======================================================================
# PART 8 — THE ONE-CLICK API: configure() one app, then sign() requests.
# =======================================================================

_cfg = {}
DESC9 = None                             # descriptor #9 — set by configure()
ADJ_SIGNING_ID = "1500000"               # pinned claim + header value
ADJ_VERIFICATION = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
CLIENT_SDK = "android5.7.0"              # Client-SDK header + claims client_sdk
NATIVE_VERSION = "5.0.0"
HEADERS_ID = "10"


def configure(campaign_data):
    """Patch the per-app constants from campaign_data (one app).  The only
    REQUIRED key is cert_sha1; the rest have safe defaults.  Call once
    before any sign()."""
    global _cfg, DESC9, ADJ_SIGNING_ID, ADJ_VERIFICATION, NATIVE_VERSION
    global CLIENT_SDK, HEADERS_ID
    _cfg = dict(campaign_data)
    if _cfg.get("algorithm", "adj9") != "adj9":
        print("[SIGNER] WARNING: algorithm=%r is not adj9"
              % _cfg.get("algorithm"), flush=True)
    DESC9 = bytes.fromhex(_cfg["cert_sha1"])
    ADJ_SIGNING_ID = str(_cfg.get("adj_signing_id", ADJ_SIGNING_ID))
    ADJ_VERIFICATION = str(_cfg.get("adj_verification", ADJ_VERIFICATION))
    NATIVE_VERSION = str(_cfg.get("native_version", NATIVE_VERSION))
    CLIENT_SDK = str(_cfg.get("client_sdk", CLIENT_SDK))
    HEADERS_ID = str(_cfg.get("headers_id", HEADERS_ID))
    return _cfg


def _parse_head(v):
    """head_phase config string ("2b" / "2b,48") -> tuple."""
    if isinstance(v, str):
        return tuple(int(x, 16) for x in v.replace(":", ",").split(",")
                     if x.strip())
    return tuple(v)


def sign_request(params, kind, head=None, second=None, seed=None):
    """One fresh signing: own clock second, own seed S, own claims.

    params : the request's wire fields as a dict (device data / click fields)
    kind   : "session" | "click" | "attribution"
    head   : the d0 selector phase, or None -> a fresh random selector.
             The phase is provably a free value: the server cannot verify
             it (live-verified with a non-pool value, funnel_random_phase).
    returns (blob_192B, second, info)
    """
    if DESC9 is None:
        raise RuntimeError("call configure(campaign_data) first "
                           "(it sets cert_sha1)")
    if head is None:
        head = (os.urandom(1)[0] % 127,)   # fresh selector 0..126:
        # keeps the expansion mask (s<<1)+3 inside 8 bits, the domain
        # the native's selector formula operates in (pool max 72)
    val = dict(params)
    val.update({"activity_kind": kind, "client_sdk": CLIENT_SDK,
                "adj_signing_id": ADJ_SIGNING_ID, "headers_id": HEADERS_ID,
                "native_version": NATIVE_VERSION,
                "adj_verification": ADJ_VERIFICATION})
    second = int(second if second is not None else time.time())
    seed = int.from_bytes(os.urandom(4), "big") if seed is None else int(seed)
    cb = build_claims(val, kind)
    blob = sign_pure(second, seed, cb, d9_hex=DESC9.hex(),
                     kind=kind, head=head)
    info = {"S": seed, "kind": kind, "claims_len": len(cb), "head": head,
            "second": second}
    return blob, second, info


def sign(params, kind, head=None, second=None, seed=None):
    """sign_request with configure()'s head_phase override (explicit head
    still wins; None -> random phase).  returns (blob, second, info). ~3 ms."""
    if head is None and _cfg.get("head_phase"):
        head = _parse_head(_cfg["head_phase"])
    return sign_request(params, kind, head=head, second=second, seed=seed)


def auth_header(blob):
    """The Authorization header value for a minted blob."""
    return ('Signature signature="%s",adj_signing_id="%s",algorithm="adj9",'
            'headers_id="%s",native_version="%s",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), ADJ_SIGNING_ID, HEADERS_ID,
               NATIVE_VERSION, ADJ_VERIFICATION))


def api_host():
    """The Adjust API host for this app's requests."""
    return _cfg.get("api_host", "app.adjust.com")


def client_sdk():
    """The Client-SDK header value for every request."""
    return CLIENT_SDK


def status():
    """A human-readable config summary (for the funnel's startup print)."""
    cert = _cfg.get("cert_sha1", "?")
    return ("[SIGNER] app            : %s\n"
            "[SIGNER] cert_sha1      : %s... (%d B)\n"
            "[SIGNER] adj_signing_id : %s   headers_id: %s\n"
            "[SIGNER] client_sdk     : %s   (Client-SDK header + claim)\n"
            "[SIGNER] native_version : %s   adj_verification: %s\n"
            "[SIGNER] head_phase     : %s   api_host: %s\n"
            "[SIGNER] engine         : closed-form algorithm, ~3 ms/signing"
            % (_cfg.get("package_name", "?"),
               cert[:16], len(cert) // 2,
               ADJ_SIGNING_ID, HEADERS_ID,
               CLIENT_SDK, NATIVE_VERSION, ADJ_VERIFICATION,
               _cfg.get("head_phase", "(default 2b)"), api_host()))


# =======================================================================
# PART 9 — SELF-TEST: 9 genuine device captures frozen INSIDE this file
# (3 creditsea SDK-5.8.0 + 6 penti SDK-5.7.0): the claims law per capture
# plus the full 192-B mints, byte-exact.  No external resource is needed —
# the file is complete on its own.
# =======================================================================
GOLD_JSON = r"""[{"S":3409741912,"app":"creditsea","blob_hex":"26148db92c7134c438f3b3d7219b36841e08eab70fdabe6417ef02699c35d055d3f45c03d69cdc9db912b0e49fe2d1289bfa5005d861c8953a90c613d0eddd6fc6477e5d947fc6c4a5684d9ea0b191dac317f1142982fdd4c23c1cfd0c68b0578179f15fa1f5cb99fe9618d9a4b43c63c061fb3ea1098b1d331f543f3f80981e13fa314b3a922ec74010d0452a3f35bec0428ace2c4602e669f777a429bc845c18bbb292ac2eb866bdbbf6193af2743650a77bb3be45499d5b793aeb598e7fc7","claims_sha256":"249f385041c4007b185c7ff2531269418eb7b8ab25b2b234713d9058d3a7452e","d9_hex":"06f5ffcee0541608765407ab9e0180e7b1b7e7d0","head":[43],"kind":"session","map":{"activity_kind":"session","adj_signing_id":"1500000","adj_verification":"KlcAG2cbAAsKSl1KVi0FGiJbDHMI","algorithm":"adj9","android_uuid":"79457bcc-b9e1-4ac3-a463-f435727cd358","api_level":"31","app_token":"i2n2e5kmcpvk","app_version":"1.0.174","attribution_deeplink":"1","client_sdk":"flutter5.8.0@android5.8.0","connectivity_type":"1","country":"IN","cpu_type":"arm64-v8a","created_at":"2026-09-29T20:32:37.761Z+0530","device_manufacturer":"motorola","device_name":"moto g42","device_type":"phone","display_height":"2237","display_width":"1080","enqueue_size":"0","environment":"production","first_error":"0","foreground":"1","gps_adid":"b9f64a28-7fd6-4cfd-a85a-2c272234b6e4","gps_adid_attempt":"1","gps_adid_src":"service","hardware_name":"S2SE32.28-28-4","headers_id":"10","initiating_package_name":"com.android.vending","installed_at":"2026-09-29T18:04:43.560Z+0530","language":"en","last_error":"0","native_version":"5.0.0","needs_response_details":"1","offline_mode_enabled":"0","os_build":"S2SE32.28-28-4","os_name":"android","os_version":"12","package_name":"com.creditsea.app","retry_count":"0","screen_density":"high","screen_format":"long","screen_size":"normal","sent_at":"2026-09-29T20:32:37.816Z+0530","session_count":"1","store_name_from_system":"com.android.vending","tracking_enabled":"1","ui_mode":"1","updated_at":"2026-09-29T18:04:43.560Z+0530","wait_time":"0.0","wait_total":"0.0"},"second":1790694158,"unpadded_len":380},{"S":2096874977,"app":"creditsea","blob_hex":"1324ef343e3d350b0ddf4f523fce48b347ee7dd4c886a9e4d1aaa672042420ad9fd7adce1e4bcb444fbd73938b8a70bee667e599eb9a38d8fc99d0772141ce88fdba16d9e4a8b95a47b2585daec2953f5a2ddf6eec8e033179e467f3cd8d6f45d5262fa68e771fbea8c137f659d89991864766e2a1efb939903eeee7780a5707e95c76f938233f74ce0810f3f1aced1c98e4614d30fdc19e79672d625a87c39a7a44bea389fd01a48fe61b08cee6377bfdefcd42a293367f70bb3eaa47ac1550","claims_sha256":"ff32b385605ad206e87335394051126bda5c8b3dcfa09b2b9b968a15719f85c5","d9_hex":"06f5ffcee0541608765407ab9e0180e7b1b7e7d0","head":[43],"kind":"click","map":{"activity_kind":"click","adj_signing_id":"1500000","adj_verification":"KlcAG2cbAAsKSl1KVi0FGiJbDHMI","algorithm":"adj9","android_uuid":"79457bcc-b9e1-4ac3-a463-f435727cd358","api_level":"31","app_token":"i2n2e5kmcpvk","app_version":"1.0.174","attribution_deeplink":"1","click_time":"2026-09-29T18:04:19.000Z+0530","click_time_server":"2026-09-29T18:04:18.000Z+0530","client_sdk":"flutter5.8.0@android5.8.0","connectivity_type":"1","country":"IN","cpu_type":"arm64-v8a","created_at":"2026-09-29T20:32:37.847Z+0530","device_manufacturer":"motorola","device_name":"moto g42","device_type":"phone","display_height":"2237","display_width":"1080","environment":"production","foreground":"1","google_play_instant":"0","gps_adid":"b9f64a28-7fd6-4cfd-a85a-2c272234b6e4","gps_adid_attempt":"1","gps_adid_src":"service","hardware_name":"S2SE32.28-28-4","headers_id":"10","install_begin_time":"2026-09-29T18:04:24.000Z+0530","install_begin_time_server":"2026-09-29T18:04:23.000Z+0530","install_version":"1.0.174","installed_at":"2026-09-29T18:04:43.560Z+0530","language":"en","native_version":"5.0.0","needs_response_details":"1","offline_mode_enabled":"0","os_build":"S2SE32.28-28-4","os_name":"android","os_version":"12","package_name":"com.creditsea.app","referrer":"adjust_reftag=cAPNPNvIUEEhy","referrer_api":"google","screen_density":"high","screen_format":"long","screen_size":"normal","sent_at":"2026-09-29T20:32:37.875Z+0530","session_count":"1","session_length":"0","source":"install_referrer","subsession_count":"1","time_spent":"0","tracking_enabled":"1","ui_mode":"1","updated_at":"2026-09-29T18:04:43.560Z+0530"},"second":1790694159,"unpadded_len":516},{"S":1354972299,"app":"creditsea","blob_hex":"23d5723505a22701424476ae2658a46561a634a2fb5827b1e3e80134e24f7c26686c6a88e8c3be3f769b4faa56f8920127426ba606a561970c241525a74365e13888b29f661203be3a2bec8f068f5042afe801faa97b7e6f48edea909a4f6f1dc97a41a5e3c807cf2d19adee7407e3b5d155d8fb9753ad29f29a53ce51e04eeb33a2e487f825f0733b8edf2867c23b3628188b64c5521e927562a180ce6a6a5a4ab31043f17660428badf14d9a643c8cd0b8cab028a12e3abdc5307709731ebf","claims_sha256":"28bf37c57aa9bf555fb47af1fff2ff790e320d92cdb6ef1abb26a8578227e37e","d9_hex":"06f5ffcee0541608765407ab9e0180e7b1b7e7d0","head":[43],"kind":"attribution","map":{"activity_kind":"attribution","adj_signing_id":"1500000","adj_verification":"KlcAG2cbAAsKSl1KVi0FGiJbDHMI","algorithm":"adj9","android_uuid":"79457bcc-b9e1-4ac3-a463-f435727cd358","api_level":"31","app_token":"i2n2e5kmcpvk","app_version":"1.0.174","attribution_deeplink":"1","client_sdk":"flutter5.8.0@android5.8.0","created_at":"2026-09-29T20:32:45.608Z+0530","device_name":"moto g42","device_type":"phone","environment":"production","foreground":"1","gps_adid":"b9f64a28-7fd6-4cfd-a85a-2c272234b6e4","gps_adid_attempt":"1","gps_adid_src":"service","headers_id":"10","initiated_by":"backend","native_version":"5.0.0","needs_response_details":"1","offline_mode_enabled":"0","os_name":"android","os_version":"12","package_name":"com.creditsea.app","sent_at":"2026-09-29T20:32:45.656Z+0530","tracking_enabled":"1","ui_mode":"1"},"second":1790694166,"unpadded_len":264},{"S":2848944211,"app":"penti","blob_hex":"60df78e44167d71852d4963377bd4ca79226d50fe8b3e0d510057b043a64ce2fd8d034cd4356d89f6031a4ed392d98a603de5223e7f20f6f2055bc58baf055968768be941325af89287b16236c98d709401a17f475c73993d03bdb10806f0b1a67c00b10b219d04634de043efe8422129676f76c9dce445afe21c6a4d0d8e8b675839d0c2cc5f06a3923dcc92b8f34e5537e8a8cf855820a6b7cac687ce9e22d15e1c73b256cbc3f6edc5d08169a6ddc6448a5516f03bbea6489686fe4e252c3","claims_sha256":"002dfa049795b72a93b052c2d057fcb59f830272d3d7dd73699efe9133301991","d9_hex":"fad0f10d60f93c17937b2f1eb6c09691ae7d74bd","head":[43],"kind":"session","map":{"activity_kind":"session","adj_signing_id":"1500000","adj_verification":"KlcAG2cbAAsKSl1KVi0FGiJbDHMI","algorithm":"adj9","android_uuid":"1b06322b-9070-4bdc-a231-2199bef3f3f5","api_level":"31","app_token":"jut9tib0eeps","app_version":"3.14.0","attribution_deeplink":"1","client_sdk":"android5.7.0","connectivity_type":"1","cpu_type":"arm64-v8a","created_at":"2026-09-25T18:35:08.025Z+0530","device_manufacturer":"motorola","device_name":"moto g42","device_type":"phone","display_height":"2237","display_width":"1080","enqueue_size":"0","environment":"production","first_error":"0","foreground":"1","gps_adid":"7cc81be0-60a0-4342-a878-eb5ee4f2634a","gps_adid_attempt":"1","gps_adid_src":"service","hardware_name":"S2SE32.28-28-4","headers_id":"10","initiating_package_name":"com.android.vending","installed_at":"2026-09-14T17:52:12.431Z+0530","language":"tr","last_error":"0","native_version":"5.0.0","needs_response_details":"1","offline_mode_enabled":"0","os_build":"S2SE32.28-28-4","os_name":"android","os_version":"12","package_name":"com.penti.app","retry_count":"0","screen_density":"high","screen_format":"long","screen_size":"normal","sent_at":"2026-09-25T18:35:08.070Z+0530","session_count":"1","store_name_from_system":"com.android.vending","tracking_enabled":"1","ui_mode":"1","updated_at":"2026-09-24T20:36:30.448Z+0530","wait_time":"0.0","wait_total":"0.0"},"second":1790341508,"unpadded_len":360},{"S":3290869532,"app":"penti","blob_hex":"3926cc0606ae7c3c3b162d3c6eddc009c8f2d8397416ed138dc3a5120b3059a094a05d6020e76af776d74804b07c9ceaa492bf5d4346272435fa11cdb1cf5380afc69b675a0ec7db8d0cf59e2ac1e17268adbce46a61c1733b0823d3c0f9884e588e083e3d3c4a49ea1aa7666920ce5b2c235074f0e7545bcdc65ab1d07df6345bfd05a0f076332e00f11cd745c0888759274db6c418ac9bc7038b928cfd2fa613fc577d4a13cef4cd6cab4514271f301d42195a0dd442f4dbdd42f111eab679","claims_sha256":"4c1924e221f5279b2f723ba251de3fe8117bc9740481669bdf47174079604507","d9_hex":"fad0f10d60f93c17937b2f1eb6c09691ae7d74bd","head":[43],"kind":"click","map":{"activity_kind":"click","adj_signing_id":"1500000","adj_verification":"KlcAG2cbAAsKSl1KVi0FGiJbDHMI","algorithm":"adj9","android_uuid":"1b06322b-9070-4bdc-a231-2199bef3f3f5","api_level":"31","app_token":"jut9tib0eeps","app_version":"3.14.0","attribution_deeplink":"1","client_sdk":"android5.7.0","connectivity_type":"1","cpu_type":"arm64-v8a","created_at":"2026-09-25T18:35:08.096Z+0530","device_manufacturer":"motorola","device_name":"moto g42","device_type":"phone","display_height":"2237","display_width":"1080","environment":"production","foreground":"1","google_play_instant":"0","gps_adid":"7cc81be0-60a0-4342-a878-eb5ee4f2634a","gps_adid_attempt":"1","gps_adid_src":"service","hardware_name":"S2SE32.28-28-4","headers_id":"10","installed_at":"2026-09-14T17:52:12.431Z+0530","language":"tr","native_version":"5.0.0","needs_response_details":"1","offline_mode_enabled":"0","os_build":"S2SE32.28-28-4","os_name":"android","os_version":"12","package_name":"com.penti.app","referrer":"utm_source=google-play&utm_medium=organic","referrer_api":"google","screen_density":"high","screen_format":"long","screen_size":"normal","sent_at":"2026-09-25T18:35:08.126Z+0530","session_count":"1","session_length":"0","source":"install_referrer","subsession_count":"1","time_spent":"0","tracking_enabled":"1","ui_mode":"1","updated_at":"2026-09-24T20:36:30.448Z+0530"},"second":1790341509,"unpadded_len":387},{"S":2771381211,"app":"penti","blob_hex":"520bea1505cbc87565c26b035e4ce43fd2124166cf326b2843fe1f8d8bb02cd18c30b85a08bd0925ebae1d7de5c93a440058d4753f8fc4d21c3ff4f5acc9c3006cc161008525e4faa5e0dce4244a17f313aae5ade3ae82356fdce645b6f3261315cb9f43ad7dc8b630e41fc0a440bdab8d226333f1aebb3822d48b1354dcc6a056774fd64585176d603f289bba1e2446733aa5572cc96eaa2fb4bd4f2460cad6b09a72e63e5fd3b1993b366c6e90f0837c6e1353723ee7c8ed4e4607ec962391","claims_sha256":"c5e0ddcb054eeac45362b380c5636bb080d78f47db82a749b00689ec72286659","d9_hex":"fad0f10d60f93c17937b2f1eb6c09691ae7d74bd","head":[43,72],"kind":"session","map":{"activity_kind":"session","adj_signing_id":"1500000","adj_verification":"KlcAG2cbAAsKSl1KVi0FGiJbDHMI","algorithm":"adj9","android_uuid":"5e14e0e7-41c3-471d-8b58-5d4767a008e6","api_level":"31","app_token":"jut9tib0eeps","app_version":"3.13.9","attribution_deeplink":"1","client_sdk":"android5.7.0","connectivity_type":"1","cpu_type":"arm64-v8a","created_at":"2026-09-24T19:03:24.928Z+0200","device_manufacturer":"motorola","device_name":"moto g42","device_type":"phone","display_height":"2237","display_width":"1080","enqueue_size":"0","environment":"production","first_error":"0","foreground":"1","gps_adid":"2db6422f-0045-41bd-99ef-2264d70beec9","gps_adid_attempt":"1","gps_adid_src":"service","hardware_name":"S2SE32.28-28-4","headers_id":"10","initiating_package_name":"com.android.vending","installed_at":"2026-09-24T19:03:25.431Z+0200","language":"tr","last_error":"0","native_version":"5.0.0","needs_response_details":"1","offline_mode_enabled":"0","os_build":"S2SE32.28-28-4","os_name":"android","os_version":"12","package_name":"com.penti.app","retry_count":"0","screen_density":"high","screen_format":"long","screen_size":"normal","sent_at":"2026-09-24T19:03:24.942Z+0200","session_count":"1","store_name_from_system":"com.android.vending","tracking_enabled":"1","ui_mode":"1","updated_at":"2026-09-24T19:03:25.431Z+0200","wait_time":"0.0","wait_total":"0.0"},"second":1790341510,"unpadded_len":360},{"S":2161973750,"app":"penti","blob_hex":"7cb6ef3f19e9cea901be35cc251275909260e77fa06a05684525f4d653c8b14302bc765b72415677027f5b4e7a392b2928b877d93a0118661b2c5bb2f21693323ef04bc3908d95b30710d0bf00065dd8b38bb41a584a1b487f2db427e9b38cb3fcd646c8a636de85372786a955f83582671f8d772c2895f013a4ca3e31abb39f568910012baf4c12b5105ab2b7dbe5cdb8ce9a5a3724b9784ec6df5f5221f48ba86698310cb3bb896b09259fa5ef74cf0a15ac037e2c1276448f43efb58b1db2","claims_sha256":"431982c612c1a0c1e6d5ceff503e99d6ef7c9fe8a33afc376b20e00c0554fb94","d9_hex":"fad0f10d60f93c17937b2f1eb6c09691ae7d74bd","head":[43,72],"kind":"click","map":{"activity_kind":"click","adj_signing_id":"1500000","adj_verification":"KlcAG2cbAAsKSl1KVi0FGiJbDHMI","algorithm":"adj9","android_uuid":"5e14e0e7-41c3-471d-8b58-5d4767a008e6","api_level":"31","app_token":"jut9tib0eeps","app_version":"3.13.9","attribution_deeplink":"1","click_time":"2026-09-24T19:03:17.000Z+0200","click_time_server":"2026-09-24T19:03:15.000Z+0200","client_sdk":"android5.7.0","connectivity_type":"1","cpu_type":"arm64-v8a","created_at":"2026-09-24T19:03:24.961Z+0200","device_manufacturer":"motorola","device_name":"moto g42","device_type":"phone","display_height":"2237","display_width":"1080","environment":"production","foreground":"1","google_play_instant":"0","gps_adid":"2db6422f-0045-41bd-99ef-2264d70beec9","gps_adid_attempt":"1","gps_adid_src":"service","hardware_name":"S2SE32.28-28-4","headers_id":"10","install_begin_time":"2026-09-24T19:03:23.000Z+0200","install_begin_time_server":"2026-09-24T19:03:21.000Z+0200","install_version":"3.13.9","installed_at":"2026-09-24T19:03:25.431Z+0200","language":"tr","native_version":"5.0.0","needs_response_details":"1","offline_mode_enabled":"0","os_build":"S2SE32.28-28-4","os_name":"android","os_version":"12","package_name":"com.penti.app","referrer":"utm_source=google-play&utm_medium=organic","referrer_api":"google","screen_density":"high","screen_format":"long","screen_size":"normal","sent_at":"2026-09-24T19:03:24.970Z+0200","session_count":"1","session_length":"0","source":"install_referrer","subsession_count":"1","time_spent":"0","tracking_enabled":"1","ui_mode":"1","updated_at":"2026-09-24T19:03:25.431Z+0200"},"second":1790341511,"unpadded_len":509},{"S":2820583385,"app":"penti","blob_hex":"5de779694994be397d1ab25c35306f9d193d9ea2f9bc77d43150ce5ec5373ab7a343010c6c715f781845954ded2fd38b9d1b8d5dbbd6017b39a9c111edae3ea67c4d8c0a59213b24c9f344ec659124416ab388cd52bca23594712d7a5b95ab9d14489e1f628d31aa7995baec4bf7068417fa5b163357cf3d7425ce9a0b72784c2f529105e49b632ac43e6d6db41a96cdba16d0f381776651d4bf154474d36c0b3ce32acb8403ee3530311a920d1575e4a4a4b33c44739f477b88b55f1c9ec764","claims_sha256":"2ba49f0a4618f5b5a90e9e97db8ef6b9be34d074c2886a9eb97998fcfb2c68e7","d9_hex":"fad0f10d60f93c17937b2f1eb6c09691ae7d74bd","head":[43,72],"kind":"attribution","map":{"activity_kind":"attribution","adj_signing_id":"1500000","adj_verification":"KlcAG2cbAAsKSl1KVi0FGiJbDHMI","algorithm":"adj9","android_uuid":"5e14e0e7-41c3-471d-8b58-5d4767a008e6","api_level":"31","app_token":"jut9tib0eeps","app_version":"3.13.9","attribution_deeplink":"1","client_sdk":"android5.7.0","created_at":"2026-09-24T19:03:24.666Z+0200","device_name":"moto g42","device_type":"phone","environment":"production","foreground":"1","gps_adid":"2db6422f-0045-41bd-99ef-2264d70beec9","gps_adid_attempt":"1","gps_adid_src":"service","headers_id":"10","initiated_by":"backend","native_version":"5.0.0","needs_response_details":"1","offline_mode_enabled":"0","os_name":"android","os_version":"12","package_name":"com.penti.app","sent_at":"2026-09-24T19:03:24.696Z+0200","tracking_enabled":"1","ui_mode":"1"},"second":1790341512,"unpadded_len":246},{"S":1854755305,"app":"penti","blob_hex":"43db3f967ae28ce90efee9f35c5e4f57fb144e56385559ff11dc66b440bdc7056c3e7ae86f37c993b70cecb9373c0bc54701b251f7030559466eb3fe0093aafe5a08c8a3b8927a5b9b4dd2b23bcc62f2e8b48ac17fe6a766b89f8982c274cd565f1189954b9312bcb3913e5fc5acfc121924f9cee1a9d38c0efa840a07487e44787da273d764b7daf3b3b6d0e99fe4e25027d25e1c818f2e90e7daec3f93820d031c74d94f1628273a865b5849a3acebe30abd5e63bfa2d52c31fd416689fd80","claims_sha256":"e4f6295e8320f0b7e36f55660f2a23a6db55dfea6dc2167c60acc53042419d84","d9_hex":"fad0f10d60f93c17937b2f1eb6c09691ae7d74bd","head":[43],"kind":"attribution","map":{"activity_kind":"attribution","adj_signing_id":"1500000","adj_verification":"KlcAG2cbAAsKSl1KVi0FGiJbDHMI","algorithm":"adj9","android_uuid":"1b06322b-9070-4bdc-a231-2199bef3f3f5","api_level":"31","app_token":"jut9tib0eeps","app_version":"3.14.0","attribution_deeplink":"1","client_sdk":"android5.7.0","created_at":"2026-09-25T18:35:12.111Z+0530","device_name":"moto g42","device_type":"phone","environment":"production","foreground":"1","gps_adid":"7cc81be0-60a0-4342-a878-eb5ee4f2634a","gps_adid_attempt":"1","gps_adid_src":"service","headers_id":"10","initiated_by":"backend","native_version":"5.0.0","needs_response_details":"1","offline_mode_enabled":"0","os_name":"android","os_version":"12","package_name":"com.penti.app","sent_at":"2026-09-25T18:35:12.142Z+0530","tracking_enabled":"1","ui_mode":"1"},"second":1790341513,"unpadded_len":246}]"""
GOLD_VECTORS = json.loads(GOLD_JSON)


def self_test(verbose=True):
    """Claims-law check: build every capture's #10 string, compare sha256."""
    ok = True
    for g in GOLD_VECTORS:
        raw = build_claims(g["map"], g["kind"])
        sha = hashlib.sha256(raw).hexdigest()
        good = len(raw) == g["unpadded_len"] and sha == g["claims_sha256"]
        if verbose:
            print("[SIGNER] law  %-9s %-11s len=%3d (want %3d)  %s"
                  % (g["app"], g["kind"], len(raw), g["unpadded_len"],
                     "OK" if good else "FAIL"))
        ok &= good
    return ok


def self_test_blob(verbose=True):
    """Full-blob check: mint every genuine capture from (second, S, claims,
    d9, head) and require byte equality."""
    ok = True
    dt = 0.0
    for g in GOLD_VECTORS:
        t0 = time.perf_counter()
        blob = sign_pure(g["second"], g["S"], g["map"],
                         d9_hex=g["d9_hex"], kind=g["kind"],
                         head=tuple(g["head"]))
        dt = max(dt, time.perf_counter() - t0)
        good = blob.hex() == g["blob_hex"]
        if verbose:
            print("[SIGNER] blob %-9s %-11s second=%d  %s  (%.2f ms)"
                  % (g["app"], g["kind"], g["second"],
                     "BYTE-EXACT" if good else "FAIL", dt * 1000.0))
        ok &= good
    if verbose and GOLD_VECTORS:
        print("[SIGNER] worst signing: %.2f ms" % (dt * 1000.0))
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv or "--vm" in sys.argv:
        _t0 = time.perf_counter()
        _ok = self_test()
        _ok = self_test_blob() and _ok
        print("[SIGNER] self_test -> %s (%.2f s total)"
              % ("OK" if _ok else "FAIL", time.perf_counter() - _t0),
              flush=True)
        sys.exit(0 if _ok else 1)
    print("[SIGNER] adj9_signer — the adj9 signature algorithm in closed "
          "form (stdlib only).")
    print("[SIGNER] use: configure(campaign_data) -> sign(params, kind) "
          "-> auth_header(blob)")
    print("[SIGNER] test: python adj9_signer.py --selftest")
