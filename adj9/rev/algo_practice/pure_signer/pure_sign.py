"""pure_sign.py — the adj9 signature algorithm in closed form, stdlib only.

    blob(192) = header(16) || whiten(record(144), header) || digest(32)

One signing ~3 ms (the FinEx VM interpreter took 15-25 s).  Every claim
below is proven byte-exact against 9 genuine device captures (3 creditsea
SDK-5.8.0 + 6 penti SDK-5.7.0) plus 6 controlled VM probes — run the gate:

    python pure_sign.py

LAYOUT:  PART 0 constants · PART 1 header · PART 2 region · PART 3 claims
         PART 4 block hash · PART 5 whitening · PART 6 digest · PART 7 signer
         then the validation gate (reverse-engineering utilities live there).

  1. header(16)   bionic srand(second): the MINSTD rand (x = 16807*x mod
                  2^31-1) warmed up 310 draws, then 8 draws XORed in pairs,
                  each pair big-endian.
  2. region       seed S -> d0/d2/d4: a shuffle + bit-transpose gives d4;
                  d0 = selector halfwords (the head phase, then the fixed
                  0x40|(i&7) cycle); d2 = LE32(S) re-read big-endian — which
                  is why the record carries S big-endian at [20:24).
  3. record(144)  01 00 08 | head16 | 02 | BE32(S) | 03 | D9 | 04 | BLOCK |
                  05 | sha256("") | 06 01 07 | 00*14 | 0000 | 0e*14
                  (D9 = the APK certificate SHA-1.)
  4. BLOCK(32)    SHA-256 with the standard padding and round constants but
                  chained from the custom IV2, over
                  D9 || 00 08 || head16 || LE32(S) || sha256("") || 01 ||
                  00*16 || claims (unpadded).  Note LE32(S) here vs the
                  record's BE32(S) — both serialisations are real.
  5. whitening    a 14-round SPN over 9 chunks of 16 B, CBC-chained from the
                  header: ADDROUNDKEY -> SBOX -> SHIFTROWS -> MIX (MIX
                  skipped on the last round), then the final key.  SBOX =
                  the AES S-box (generated); PI = each row of the 4x4 matrix
                  rotated right by its row index (generated); F = the
                  AES-xtime byte-circulant (generated).
  6. digest(32)   sha256((K^opad) || opad || sha256((K^ipad) || ipad ||
                  body)) — the pads are hashed twice, NOT standard HMAC.
  7. claims       ONE presence-filtered law for SDK 5.7.0 and 5.8.0: the
                  sorted profile keys present (values only) + the pinned
                  '1500000' + the sorted tail keys present + activity_kind +
                  client_sdk + headers_id + native_version.

Stored values: only the cipher's three secrets (KB, IV2, K) — PART 0.
Everything else is computed from logic.
"""
from __future__ import annotations

import hashlib
import struct

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
# __main__ - THE GATE (data loading only; the signer above is stdlib-only)
# =======================================================================
import base64          # noqa: E402  (gate helpers only)
import json            # noqa: E402
import os              # noqa: E402
import re              # noqa: E402
import sys             # noqa: E402
import time            # noqa: E402

# ----------------------------------------------------------------------
# reverse-engineering utilities (NOT part of the signing path)
# ----------------------------------------------------------------------
HEAD_FIRST_48 = (43, 72)
HEAD_RESIGN = (43, 7, 34, 46)


def solve_head_phase(S, want_head16, candidates=None):
    """Which known selector phase reproduces `want_head16`?  Returns the
    phase tuple, or None."""
    if candidates is None:
        candidates = (HEAD_FIRST, HEAD_FIRST_48, HEAD_RESIGN, (0x2B, 0x07),
                      (0x2B, 0x22), (0x2B, 0x22, 0x25), (0x2B, 0x05),
                      (0x2B, 0x4A, 0x05), (0x22, 0x2E), (0x30,))
    for ph in candidates:
        if head16_for(S, ph) == want_head16:
            return ph
    return None


def decode_blob(blob):
    """192-B blob -> the recovered record parts."""
    blob = bytes(blob)
    if len(blob) != 192:
        raise ValueError('blob must be 192 bytes, got %d' % len(blob))
    header, body = blob[:16], blob[16:160]
    record = whiten_body_inverse(body, header)
    return {
        "header": header,
        "record": record,
        "head": record[3:19],
        "S": int.from_bytes(record[20:24], "big"),
        "d2w_le": int.from_bytes(record[20:24], "little"),
        "d9": record[25:45],
        "block": record[46:78],
        "digest": blob[160:192],
    }


RECORD_CONSTS = (
    ((0, 3), b"\x01\x00\x08"),
    ((19, 20), b"\x02"),
    ((24, 25), b"\x03"),
    ((45, 46), b"\x04"),
    ((78, 79), b"\x05"),
    ((79, 111), SHA0),
    ((111, 114), b"\x06\x01\x07"),
    ((114, 128), b"\x00" * 14),
    ((130, 144), b"\x0e" * 14),
)


def record_consts_ok(record):
    return all(record[a:b] == want for (a, b), want in RECORD_CONSTS)


# ----------------------------------------------------------------------
# gate-only: the INVERSE cipher (decoder) and the reference cert values.
# The signing path above never uses these.
# ----------------------------------------------------------------------
def _invert_rows(rows):
    """Invert a 32x32 GF(2) bit-matrix given as row masks."""
    n = len(rows)
    m = [(rows[j], 1 << j) for j in range(n)]
    for c in range(n):
        p = next((r for r in range(c, n) if (m[r][0] >> c) & 1), None)
        if p is None:
            raise ValueError("F singular?!")
        m[c], m[p] = m[p], m[c]
        for r in range(n):
            if r != c and (m[r][0] >> c) & 1:
                m[r] = (m[r][0] ^ m[c][0], m[r][1] ^ m[c][1])
    inv = [0] * n
    for r in range(n):
        if m[r][0] != (1 << r):
            raise ValueError("F inversion failed")
        inv[r] = m[r][1]
    return inv


F_MINV = _invert_rows(F_ROWS)
_FMINV_TAB = _byte_tables(F_MINV)
_PI_INV = [0] * 16
for _i, _p in enumerate(_derive_pi()):
    _PI_INV[_p] = _i


def _F_inv(chunk):
    return b"".join(_apply_tab(_FMINV_TAB,
                               int.from_bytes(chunk[4 * b:4 * b + 4],
                                              "little")).to_bytes(4, "little")
                    for b in range(4))


def _pi1_inv(chunk):
    """undo out[_PI[i]] = in[i]  ->  in[i] = out[_PI[i]]"""
    return bytes(chunk[j] for j in _PI)


def whiten_inverse(chunk, WA):
    """Invert one whitened chunk given its WA (the previous chunk, or
    header)."""
    x = bytes(v ^ _FINAL_KEY[i] for i, v in enumerate(chunk))
    for r in range(13, -1, -1):
        if r < 13:
            x = _F_inv(x)
        x = _pi1_inv(x)
        x = bytes(SBOX_INV[v] for v in x)
        kt = _ROUND_KEYS[r]
        x = bytes(v ^ kt[i] for i, v in enumerate(x))
    return _xor(x, WA)


SBOX_INV = [0] * 256
for _v, _sv in enumerate(SBOX):
    SBOX_INV[_sv] = _v


def whiten_body_inverse(body, header):
    """body = blob[16:160), header = blob[0:16) -> the 144-B record."""
    out = bytearray()
    wa = header
    for k in range(9):
        c = body[16 * k:16 * k + 16]
        out += whiten_inverse(c, wa)
        wa = c
    return bytes(out)


D9_PENTI = "fad0f10d60f93c17937b2f1eb6c09691ae7d74bd"
D9_CREDITSEA = "06f5ffcee0541608765407ab9e0180e7b1b7e7d0"


# ---------------------------------------------------------------- gate data
def _alg():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _rev():
    return os.path.dirname(_alg())


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _phase_str(ph):
    return "(" + " ".join("%02x" % x for x in ph) + ")" if ph else "UNRESOLVED"


def _describe_mismatch(dec, got):
    rec2 = decode_blob(got)
    out = []
    if dec["header"] != rec2["header"]:
        out.append("header")
    if dec["record"] != rec2["record"]:
        bad = [j for j in range(144) if dec["record"][j] != rec2["record"][j]]
        out.append("record bytes %s (block_region=%s)"
                   % (bad[:6], all(46 <= b < 78 for b in bad)))
    if dec["digest"] != rec2["digest"]:
        out.append("digest")
    if not record_consts_ok(rec2["record"]):
        out.append("record consts BAD")
    return "; ".join(out) or "identical?"


# ------------------------------------------------------------- 1 creditsea
def _mine_creditsea():
    """(second, blob, claims map, kind) for the three genuine creditsea
    signings (testbed.mine_log over the LSPosed ground-truth log)."""
    sys.path.insert(0, os.path.join(_rev(), "creditsea"))
    import testbed                                  # noqa: E402  (gate only)
    out = []
    for s in testbed.mine_log():
        kind = s["val"].get("activity_kind", "session")
        out.append((s["second"], s["blob"], s["val"], kind))
    return out


# ------------------------------------------------------------- 2 penti wins
def _mine_penti_wins():
    """(second, blob, claims map, kind) for the six genuine penti wins."""
    lines = open(os.path.join(_rev(), "win_capture",
                              "module_win_capture.log"),
                 encoding="utf-8", errors="replace").read().split("\n")
    si = [i for i, l in enumerate(lines)
          if l.startswith("###ADJ9_BEGIN type=sign_input")]
    ah = [i for i, l in enumerate(lines)
          if l.startswith("###ADJ9_BEGIN type=authorization_header")]
    rows = _load(os.path.join(_rev(), "block_pattern_analysis.json"))["wins"]
    by_header = {bytes.fromhex(r["header"]): r for r in rows}
    out = []
    for i, j in zip(si, ah):
        val = {}
        for k in range(i, i + 12):
            if lines[k].startswith("map_order="):
                for p in lines[k][len("map_order="):].split("\x02"):
                    if "\x01" in p:
                        kk, vv = p.split("\x01", 1)
                        val[kk] = vv
                break
        blob = base64.b64decode(
            re.search(r'signature="([A-Za-z0-9+/=]+)"',
                      lines[j + 2]).group(1))
        row = by_header.get(blob[:16])
        out.append((row["second"] if row else None, blob, val,
                    val.get("activity_kind", "session")))
    return out


def _gold_check(second, gold_blob, val, kind, d9_hex):
    """Rebuild the whole blob from (second, S, claims, d9, head) and compare."""
    dec = decode_blob(gold_blob)
    S = dec["S"]
    phase = solve_head_phase(S, dec["head"])
    got = sign_pure(second, S, val, d9_hex=d9_hex, kind=kind,
                    head=phase if phase else HEAD_FIRST)
    return got == gold_blob, phase, dec, got


# --------------------------------------------------------------- 3 VM probes
_PROBE_BASE = {
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
    "android_uuid": "1b06322b-9070-4bdc-a231-2199bef3f3f5",
    "api_level": "31", "app_token": "jut9tib0eeps",
    "app_version": "3.14.0", "created_at": "2026-09-25T18:35:08.025Z+0530",
    "device_name": "moto g42", "device_type": "phone",
    "environment": "production",
    "gps_adid": "7cc81be0-60a0-4342-a878-eb5ee4f2634a",
    "gps_adid_src": "service", "hardware_name": "S2SE32.28-28-4",
    "initiating_package_name": "com.android.vending",
    "installed_at": "2026-09-14T17:52:12.431Z+0530",
    "os_build": "S2SE32.28-28-4", "os_name": "android", "os_version": "12",
    "package_name": "com.penti.app",
    "session_count": "1", "store_name_from_system": "com.android.vending",
    "tracking_enabled": "1", "updated_at": "2026-09-24T20:36:30.448Z+0530",
    "activity_kind": "session", "client_sdk": "android5.7.0",
    "adj_signing_id": "1500000", "headers_id": "10",
    "native_version": "5.0.0",
}
_PROBE_RUNS = [
    ("r0_base", 1790625704, 0xA6DA5D2B, {}),
    ("r1_sec1", 1790625705, 0xA6DA5D2B, {}),
    ("r2_seed", 1790625704, 0x11223344, {}),
    ("r3_claim", 1790625704, 0xA6DA5D2B, {"app_version": "3.14.1"}),
    ("r4_seed2", 1790625704, 0x55667788, {}),
    ("r5_sec2", 1790625706, 0xA6DA5D2B, {}),
]


def _probe_check():
    """The 6 VM probes carry no full gold blob (only the block plus the
    captured d0/d2/d4), so this re-verifies the whole record assembly."""
    ok = n = 0
    pr_dir = os.path.join(_alg(), "probes")
    for tag, sec, seed, tweak in _PROBE_RUNS:
        d = _load(os.path.join(pr_dir, "run_%s.json" % tag))
        claims = dict(_PROBE_BASE)
        claims.update(tweak)
        cb = build_claims(claims, "session")
        d0w, d2, d4w = region(seed, 0, 0, head=(0x2B, 0x48))
        d0 = b"".join(w.to_bytes(4, "big") for w in d0w)
        d4 = b"".join(w.to_bytes(4, "big") for w in d4w)
        h16 = head_words(d0w)
        head_ok = all(
            int.from_bytes(h16[4 * i:4 * i + 4], "little")
            == ((int.from_bytes(d0[4 * i:4 * i + 4], "big") & 0xFFFF) << 16)
            | (int.from_bytes(d0[4 * i:4 * i + 4], "big") >> 16)
            for i in range(4))
        d2_ok = d2 == int(d["d2"], 16)
        d4_ok = d4.hex() == "".join(d["d4"])
        blk_ok = predict_block(seed, h16, cb,
                               bytes.fromhex(D9_PENTI)).hex() == d["block_hex"]
        good = head_ok and d2_ok and d4_ok and blk_ok
        n += 1
        ok += good
        print("    %-9s d0head=%-5s d2=%-5s d4=%-5s block=%-5s  %s"
              % (tag, head_ok, d2_ok, d4_ok, blk_ok, "OK" if good else "FAIL"))
    return ok, n


# ---------------------------------------------------------------- main
def main():
    t_start = time.perf_counter()
    total_ok = total_n = 0
    print("=" * 76)
    print("pure_sign.py GATE - the complete 192-byte adj9 signature, no VM")
    print("=" * 76)

    print("\n[1] creditsea golds   (d9=%s...)" % D9_CREDITSEA[:8])
    cs = _mine_creditsea()
    ok = 0
    for n, (second, blob, val, kind) in enumerate(cs):
        good, phase, dec, got = _gold_check(second, blob, val, kind,
                                            D9_CREDITSEA)
        ok += good
        print("    gold%d %-12s second=%d S=%08x claims=%dB head=%-12s %s"
              % (n, kind, second, dec["S"], len(build_claims(val, kind)),
                 _phase_str(phase),
                 "BYTE-EXACT" if good else "FAIL " + _describe_mismatch(dec,
                                                                        got)))
    n = len(cs)
    print("    -> %d/%d byte-exact" % (ok, n))
    total_ok += ok
    total_n += n

    print("\n[2] genuine penti wins (d9=%s...)" % D9_PENTI[:8])
    wins = _mine_penti_wins()
    ok = 0
    for n, (second, blob, val, kind) in enumerate(wins):
        good, phase, dec, got = _gold_check(second, blob, val, kind, D9_PENTI)
        ok += good
        print("    win%d  %-12s second=%s S=%08x head=%-12s %s"
              % (n, kind, second, dec["S"], _phase_str(phase),
                 "BYTE-EXACT" if good
                 else "FAIL " + _describe_mismatch(dec, got)))
    n = len(wins)
    print("    -> %d/%d byte-exact" % (ok, n))
    total_ok += ok
    total_n += n

    print("\n[3] VM probes r0..r5 (record assembly vs captured d0/d2/d4/block)")
    po, pn = _probe_check()
    print("    -> %d/%d consistent" % (po, pn))
    total_ok += po
    total_n += pn

    print("\n[4] timing - 100 signings per gold claims set (pure, no VM)")
    dt = 0.0
    for second, blob, val, kind in cs:
        dec = decode_blob(blob)
        phase = solve_head_phase(dec["S"], dec["head"]) or HEAD_FIRST
        cb = build_claims(val, kind)
        sign_pure(second, dec["S"], cb, D9_CREDITSEA, kind, head=phase)
        t0 = time.perf_counter()
        for _ in range(100):
            sign_pure(second, dec["S"], cb, D9_CREDITSEA, kind, head=phase)
        d = time.perf_counter() - t0
        dt = max(dt, d)
        print("    %-12s claims %3d B -> %7.3f ms/signing  (%.4f s / 100)"
              % (kind, len(cb), d * 10.0, d))

    print("\n" + "=" * 76)
    print("TOTAL: %d/%d vectors byte-exact | worst case %.3f ms/signing "
          "(VM: 15000-25000 ms)" % (total_ok, total_n, dt * 10.0))
    print("gate wall clock: %.2f s" % (time.perf_counter() - t_start))
    print("=" * 76)
    return 0 if total_ok == total_n else 1


if __name__ == "__main__":
    sys.exit(main())
