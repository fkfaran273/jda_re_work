"""adj9_pure.py -- the Adjust adj9 signature in pure Python.  No VM.

    blob = header(16) || whitened_record(144) || digest(32)

  header     bionic rand() seeded by the signing second: 310 warm-up draws,
             then eight draws XORed in pairs.  A function of the second alone.
  record     144 bytes laid out by build_record().  The seed feeds the head;
             the request fields form the claims string.
  block      record[46:78] = SHA-256 over cert || 00 08 || head || LE32(seed)
             || sha256("") || 01 00*16 || claims -- standard everything, but
             chained from IV2 rather than the standard IV.
  whitening  a 14-round SPN, CBC from the header as IV: round key, S-box,
             ShiftRows, MixColumns.  AES-256 with a different S-box, a
             different row permutation and a different key schedule.
  digest     a two-pass SHA-256 MAC: SHA-256((K^opad)||opad||SHA-256((K^ipad)
             ||ipad||body)).  Not standard HMAC -- the pad is hashed twice.

Byte-exact against every genuine capture and against the FinEx VM itself.

USE
    blob, second, info = sign_request(fields, "session", campaign_data)
    value = authorization_header(blob, campaign_data)

FIXED PARAMETERS (recorded; everything else is computed)
    IV2  32 B  chaining value for the block hash
    K    32 B  MAC key for the digest
    KB  240 B  round-key schedule

    The SHA-256 constants come from the cube roots of 64 primes, the S-box
    from its own definition, MixColumns and ShiftRows as arithmetic.

    sign_request() draws os.urandom(4) as the seed unless you pass seed=.
    Pin it for any A/B comparison.
"""

from __future__ import annotations
import base64, datetime, hashlib, os, struct, time

# ------------------------------------------------------------------------
# DEFAULTS -- the fallbacks sign_request uses when campaign_data omits a key
# ------------------------------------------------------------------------

# The APK signing-certificate SHA-1 is the only per-app input, and it is not
# a constant here -- pass it in campaign_data["cert_sha1"].  (The bytecode
# called it "descriptor 9"; it is simply the APK's certificate hash.)

# THE HEAD PHASE: the prefix bytes of the d0 selector list.
#
# It is an input, and it does not affect attribution.  Measured all four
# combinations -- penti and creditsea each signed with (0x2b,) and with
# (0x2b,0x48) -- and every one joined to its own campaign, because the server
# does not verify the envelope.  So one value serves every app; a caller passes
# head_phase= only to reproduce a specific captured signature.
#
# It is NOT a per-app constant.  Six consecutive-second signings from ONE penti
# launch used (0x2b,) (0x2b,) (0x2b,0x48) (0x2b,0x48) (0x2b,0x48) (0x2b,).
# Nor is it derivable from anything visible: two of those are both
# activity_kind=session with every field identical, and a seed-bit search gives
# candidates a permutation test cannot separate from chance (p = 0.40).
#
# 0x2b = 43: the first selector byte every observed phase begins with.  A
# selector s selects the d4 halfwords whose bits are set in (s << 1) + 3, so
# 0x2b selects bits of mask 0x59.  The rest of the list is the generated
# cycle 0x40 | (i & 7) -- also selectors, not arbitrary data.
HEAD_PHASE_DEFAULT = (0x2B,)          # 43 -- the first selector byte


# THE CLAIMS LAW -- which request fields get signed, and in what order
# ------------------------------------------------------------------------
# ONE law covers every SDK generation.  The key lists differ slightly between
# 5.7 and 5.8, but a key is emitted only when the request map actually
# carries it non-empty, so the union of both lists produces the same bytes as
# whichever list that SDK would have used on its own.
#
# A key enters in a fixed place: sorted within the profile group, then the
# pinned adj_signing_id, then sorted within the tail, then block2.

PROFILE = [
    'adj_verification', 'android_uuid', 'api_level', 'app_token',
    'app_version', 'country', 'created_at', 'device_name', 'device_type',
    'environment', 'gps_adid', 'gps_adid_src', 'hardware_name',
    'installed_at', 'os_build', 'os_name', 'os_version', 'package_name',
    'push_token',
]

# the event endpoint adds its own fields; solved from the genuine penti capture
# in adj9/cap/oracle_run3.log, 542-byte claims for that signing
EVENT_EXTRA = ['event_count', 'event_token', 'partner_params']

ATTR_DROP = ['hardware_name', 'installed_at', 'os_build']

ATTR_EXTRA = ['initiated_by']

# kind -> (profile keys, tail keys)
_GROUPS = {
    'session': (PROFILE + ['initiating_package_name'],
                ['session_count', 'session_length', 'store_name_from_system',
                 'subsession_count', 'time_spent', 'tracking_enabled',
                 'updated_at']),
    'click': (PROFILE + ['click_time', 'click_time_server',
                         'google_play_instant', 'install_begin_time',
                         'install_begin_time_server', 'install_version',
                         'referrer', 'referrer_api'],
              ['session_count', 'session_length', 'source', 'subsession_count',
               'time_spent', 'tracking_enabled', 'updated_at']),
    'attribution': ([k for k in PROFILE if k not in ATTR_DROP] + ATTR_EXTRA,
                    ['tracking_enabled']),
    # `seq` is a TAIL key for events, not a profile key: it lands between the
    # pinned adj_signing_id and session_count in the emitted order.
    'event': (PROFILE + EVENT_EXTRA,
              ['seq', 'session_count', 'session_length', 'subsession_count',
               'time_spent', 'tracking_enabled']),
}

BLOCK2 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']

PIN = 'adj_signing_id'


def claim_key_order(val, kind):
    """Emission order: sorted profile, then PIN, then sorted tail, then block2.
    Only keys the map actually carries are emitted."""
    try:
        profile, tail = _GROUPS[kind]
    except KeyError:
        raise ValueError('claims law known for kinds: %s (got %r)'
                         % (', '.join(sorted(_GROUPS)), kind))
    keys = [k for k in sorted(profile) if val.get(k)]
    keys.append(PIN)                      # emitted pinned; read or not
    keys += [k for k in sorted(tail) if val.get(k)]
    keys += [k for k in BLOCK2 if val.get(k)]
    return keys


def claims_unpadded(val, kind):
    """The unpadded claims string -- the signed fields, concatenated."""
    keys = claim_key_order(val, kind)
    missing = [k for k in keys if k != PIN and not val.get(k)]
    if missing:
        raise KeyError('claims law missing values: %s' % missing)
    return ''.join(val[k] if k == PIN else val[k] for k in keys).encode('latin1')


def claims_padded(val, kind):
    """(padded #10 bytes, unpadded length) -- NUL-pad to a 4-byte multiple;
    the claims length is the UNPADDED length."""
    raw = claims_unpadded(val, kind)
    return raw + b"\x00" * (-len(raw) % 4), len(raw)


# both names kept so existing callers keep working; there is one law now
claims_padded_58 = claims_padded
_LAW_57 = claims_padded

# ------------------------------------------------------------------------
# THE HEADER -- 16 bytes, a pure function of the signing second
# ------------------------------------------------------------------------

# bionic's rand() is the minimal-standard Lehmer generator in Schrage's form,
# so no 64-bit multiply is needed.  Every number below follows from a small
# number of named choices rather than being arbitrary:
#
#     M      = 2**31 - 1       the Mersenne-prime modulus
#     A      = 7**5 = 16807    the multiplier
#     Q, R   = M//A, M%A      = 127773, 2836 -- the Schrage split
#     DEGREE = 31             MINSTD's polynomial has degree 31, so the
#                             state is 31 words wide
#     TAPS   = (3, 0)         bionic combines r[3] and r[0]
#     WARMUP = 310            draws discarded before the first result
#     SEED   = 0x075BD924     the zero-state default, as rand() has for
#                             srand(0).  NOT the textbook MINSTD seed
#                             123456789, which is 0x075BCD15.
_MINSTD_M = (1 << 31) - 1
_MINSTD_A = 7 ** 5
_MINSTD_Q = _MINSTD_M // _MINSTD_A
_MINSTD_R = _MINSTD_M % _MINSTD_A
_MINSTD_DEGREE = 31
_MINSTD_TAPS = (3, 0)
_MINSTD_WARMUP = 310
_MINSTD_SEED = 123459876    # 0x075BD924; NOT the textbook 123456789


class Random3:
    """bionic's rand(): a Schrage-form MINSTD generator, 31 words of state."""

    __slots__ = ("state", "fwd", "back")

    def __init__(self, seed):
        deg = _MINSTD_DEGREE
        # the seed as a signed 31-bit word; rand() never starts from zero
        s0 = seed & _MASK32
        if s0 == 0:
            s0 = 1
        prev = s0 if s0 < _MINSTD_M else s0 - 2 ** 32
        self.state = [prev] + [0] * (deg - 1)
        for i in range(1, deg):
            # Schrage's trick: one multiply of at most 31 bits each way.
            # Division must TRUNCATE toward zero, not floor, or a negative
            # state word takes a different branch than the C original.
            if prev >= 0:
                hi, lo = divmod(prev, _MINSTD_Q)
            else:
                hi = -((-prev) // _MINSTD_Q)
                lo = prev - hi * _MINSTD_Q
            word = lo * _MINSTD_A - hi * _MINSTD_R
            if word < 0:
                word += _MINSTD_M
            prev = word
            self.state[i] = word
        self.fwd, self.back = _MINSTD_TAPS
        for _ in range(_MINSTD_WARMUP):
            self.next()

    def next(self):
        """One draw: the top 31 bits of r[fwd] + r[back]."""
        st = self.state
        v = (st[self.fwd] + st[self.back]) & _MASK32
        st[self.fwd] = v if v < _MINSTD_M else v - 2 ** 32
        self.fwd = (self.fwd + 1) % _MINSTD_DEGREE
        self.back = (self.back + 1) % _MINSTD_DEGREE
        return v >> 1


def make_header(unix_sec):
    """The 16-byte header: eight draws, XORed in pairs, written big-endian.

    A pure function of the signing second -- nothing else feeds it.
    """
    r = Random3(unix_sec)
    d = [r.next() for _ in range(8)]
    return b"".join(struct.pack(">I", d[2 * i] ^ d[2 * i + 1])
                   for i in range(4))


# ------------------------------------------------------------------------
# THE REGION -- the seed-derived words, materialised from the 32-bit seed S
# ------------------------------------------------------------------------

def _mask(n: int) -> int:
    """Keep the low n bits: x & ((1 << n) - 1)."""
    return (1 << n) - 1


# The region law works on 16-bit and 32-bit lanes, so it masks to those widths.
# Derived rather than written as hex so the width is the statement.
_MASK16 = _mask(16)
_MASK31 = _mask(31)
_MASK32 = _mask(32)
_M32 = _MASK32          # same value; used by the SHA-256 helpers below

# The d0 head phase: the ONLY per-app input to the region law.  Short selector
# prefixes observed in real signatures; see HEAD_PHASE_DEFAULT above for what
# is and is not known about how the choice is made.
#
# Nothing else about d0 is stored.  Past the head prefix the selector list is
# generated as 0x40 | (i & 7); there are no selector tables here.
def _step(x: int) -> int:
    """One step of the Schrage-form MINSTD PRNG used by the header."""
    if x == 0:
        x = _MINSTD_SEED
    hi, lo = divmod(x, _MINSTD_Q)
    y = lo * _MINSTD_A - hi * _MINSTD_R
    if y < 0:
        y += _MINSTD_M
    return y & _MINSTD_M

def _shuffled_halfwords(seed: int) -> list[int]:
    """The seed -> 16 halfwords, before the transpose.

    A shuffle (not textbook Fisher-Yates: slot i is set to i rather than
    swapping contents), then one bit forced on per halfword.
    """
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

def _transpose16(pre: list[int]) -> list[int]:
    """Transpose a 16x16 bit matrix: bit (15-j) of row i moves to bit (15-i)
    of column j.  Reversible, and it only has to move bits around."""
    out = [0] * 16
    for j in range(16):
        v = 0
        for i in range(16):
            if pre[i] & (1 << (15 - j)):
                v |= 1 << (15 - i)
        out[j] = v
    return out

def _fold_selector(mask: int, source: list[int]) -> int:
    """XOR the source halfwords one 8-bit selector mask picks out."""
    value = 0
    for bit in range(8):
        if (mask >> bit) & 1:
            value ^= source[7 - bit]
    return value & _MASK16

def head16_for(seed, head=None):
    """The 16-byte head, from a seed and a selector phase.

    24 Lehmer draws -> a shuffle over 16 slots -> one bit forced per
    halfword -> the eight selector halfwords folded out of them.
    """
    phase = HEAD_PHASE_DEFAULT if head is None else tuple(head)
    source = _transpose16(_shuffled_halfwords(seed))[8:16]
    selectors = [phase[a] if a < len(phase) else (0x40 | (a & 7))   # 64 | a%8
                 for a in range(8)]
    return b"".join(_fold_selector((s << 1) + 3, source).to_bytes(2, "big")
                    for s in selectors)

# ------------------------------------------------------------------------
# SHA-256 -- the standard compression function and round constants
# ------------------------------------------------------------------------

SHA0 = hashlib.sha256(b"").digest()


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _M32

def _sha256_block(st, blk):
    w = list(blk)
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _M32)
    a, b, c, d, e, f, g, h = st
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        t1 = (h + S1 + ((e & f) ^ (~e & g)) + _K256[i] + w[i]) & _M32
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) & _M32
        h, g, f, e, d, c, b, a = (g, f, e, (d + t1) & _M32, c, b, a,
                                  (t1 + t2) & _M32)
    return [(x + y) & _M32 for x, y in zip(st, (a, b, c, d, e, f, g, h))]

def _primes(n):
    """The first n primes."""
    out, i = [], 2
    while len(out) < n:
        if all(i % p for p in out if p * p <= i):
            out.append(i)
        i += 1
    return out


def _cbrt_fraction(p, scale=1 << 32):
    """floor( frac(cbrt(p)) * scale ), in exact integers -- no floats, so
    there is no rounding to argue about."""
    k = 0
    while (k + 1) ** 3 <= p:
        k += 1
    target = p * scale ** 3
    base = k * scale
    lo, hi = 0, scale
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if (base + mid) ** 3 <= target:
            lo = mid
        else:
            hi = mid - 1
    return lo


# The SHA-256 round constants are DERIVED, not stored:  FIPS 180-4 defines
# them as the first 32 bits of the fractional parts of the cube roots of the
# first 64 primes.  Nothing here is Adjust-specific.
#
#     _K256[i] = floor( frac(cbrt(p_i)) * 2^32 )
#
# verify_K256_law.py checks this derivation two ways (exact integers, and
# 60-digit Decimal cube roots) and confirms it equals the published table.
_K256 = tuple(_cbrt_fraction(p) for p in _primes(64))


# ------------------------------------------------------------------------
# THE BLOCK -- record[46:78], SHA-256 chained from IV2 instead of the IV
# ------------------------------------------------------------------------

# The block law's chaining value.  Not a SHA-256 IV: SHA-256 chains from
# 6a09e667..., this chains from this instead.  Everything else about the hash
# -- padding, round constants -- is standard.
_BLK_IV2 = bytes.fromhex("eba2c4350f4002dc9fa8dac5127035ba"
                         "7a30ed9323473054bbe3cd00f1355ea5")

def _sha256_from_iv2(msg):
    st = list(struct.unpack(">8I", _BLK_IV2))
    m = (msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64)
         + struct.pack(">Q", len(msg) * 8))
    for i in range(0, len(m), 64):
        st = _sha256_block(st, [int.from_bytes(m[i + 4 * j:i + 4 * j + 4], "big")
                            for j in range(16)])
    return struct.pack(">8I", *st)

def record_block(head_b, seed, claims, d9):
    """record[46:78) = SHA256-IV2( D9 || 00 08 || head || LE32(S)
                                 || sha256("") || 01 00*16 || claims )"""
    msg = (d9 + b"\x00\x08" + head_b + struct.pack("<I", seed)
           + SHA0 + b"\x01" + b"\x00" * 16 + claims)
    return _sha256_from_iv2(msg)

# ------------------------------------------------------------------------
# THE DIGEST -- blob[160:192], a two-pass SHA-256 MAC
# ------------------------------------------------------------------------

# The digest law's MAC key.
_DIG_K = bytes.fromhex("690f60944dddd9847db55cd7d2d576b3"
                       "0451723fbcfa92df62b55f6fec60f2de")

_DIG_IPAD = b"\x36" * 32

_DIG_OPAD = b"\x5c" * 32

_DIG_KI = bytes(a ^ b for a, b in zip(_DIG_K, _DIG_IPAD))

_DIG_KO = bytes(a ^ b for a, b in zip(_DIG_K, _DIG_OPAD))

def record_digest(body):
    inner = hashlib.sha256(_DIG_KI + _DIG_IPAD + body).digest()
    return hashlib.sha256(_DIG_KO + _DIG_OPAD + inner).digest()

# ------------------------------------------------------------------------
# THE WHITENING CIPHER -- AES-256 with the S-box, ShiftRows and the
# key schedule replaced; only the round keys themselves are recorded
# ------------------------------------------------------------------------


# PI is AES ShiftRows: treat the chunk as a 4x4 state (byte i is row i%4,
# column i//4) and rotate each row r left by r.
# _shift_rows does out[PI[i]] = in[i];  _inv_shift_rows does out[j] = in[PI_INV[j]].
PI_INV = [4 * (((j // 4) + (j % 4)) % 4) + (j % 4) for j in range(16)]
PI = [4 * (((i // 4) - (i % 4)) % 4) + (i % 4) for i in range(16)]

# AES arithmetic, named once.
_XTIME = 0x1B          # 27  - what a byte reduces by when it carries out
_SBOX_AFFINE = 0x63    # 99  - the S-box's affine constant
_SBOX_MASK = 0x55      # 85  - this cipher's obfuscation, XOR'd either side
                          #      of the S-box; not part of AES


def _gmul(a, b):
    """Multiply in GF(2^8) mod 0x11B, the AES polynomial."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = ((a << 1) ^ _XTIME) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return p

def _gpow(a, e):
    """a^e in GF(2^8)."""
    r, base = 1, a
    while e:
        if e & 1:
            r = _gmul(r, base)
        base = _gmul(base, base)
        e >>= 1
    return r

def _rotl8(x, n):
    n %= 8
    return ((x << n) | (x >> (8 - n))) & 0xFF

def _aes_sbox():
    """The standard AES S-box, built from its definition rather than stored:
    S(x) = L(x^-1) ^ 0x63, the AES affine map."""
    out = []
    for v in range(256):
        inv = 0 if v == 0 else _gpow(v, 254)     # 0 has no inverse
        out.append(inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2)
                   ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ _SBOX_AFFINE)
    return out

_BYTE_MSBS = 0x80808080     # each byte's top bit -- the bit xtime may carry out
_BYTE_NOHI = 0xFEFEFEFE     # clears those bits, keeping the shifted bytes


def _xt(x):
    """Branch-free bytewise xtime over a whole 32-bit word: multiply every
    byte by 2, in one pass."""
    m = x & _BYTE_MSBS
    return ((x << 1) & _BYTE_NOHI) ^ (((m >> 7) * _XTIME) & _MASK32)

def mix_columns(x):
    """AES MixColumns:  y_b = 2*x_b ^ 3*x_(b+1) ^ x_(b+2) ^ x_(b+3).

    Branch-free, so it is one pass over four 32-bit words.
    """
    z = ((x >> 8) | (x << 24)) & _MASK32        # rotate right one byte
    return (_xt(x ^ z) ^ z                         # 2*(x^z) ^ z  == 2x ^ 3z
            ^ ((x >> 16) | (x << 16))              # bytes +2
            ^ ((x >> 24) | (x << 8))) & _MASK32  # bytes +3

def inv_mix_columns(y):
    """AES InvMixColumns -- the inverse circulant [14, 11, 13, 9].

        v_b = 14*b_b ^ 11*b_(b+1) ^ 13*b_(b+2) ^ 9*b_(b+3)
    """
    b = [(y >> (8 * i)) & 0xFF for i in range(4)]
    out = 0
    for i in range(4):
        v = (_gmul(14, b[i]) ^ _gmul(11, b[(i + 1) % 4])
             ^ _gmul(13, b[(i + 2) % 4]) ^ _gmul(9, b[(i + 3) % 4]))
        out |= v << (8 * i)
    return out

def _mix_chunk(chunk):
    return b"".join(mix_columns(int.from_bytes(chunk[4 * b:4 * b + 4],
                                             "little")).to_bytes(4, "little")
                    for b in range(4))

def _inv_mix_chunk(chunk):
    return b"".join(inv_mix_columns(int.from_bytes(chunk[4 * b:4 * b + 4],
                                                 "little")).to_bytes(4, "little")
                    for b in range(4))

def _shift_rows(chunk):
    out = bytearray(16)
    for i in range(16):
        out[PI[i]] = chunk[i]
    return bytes(out)

def _inv_shift_rows(chunk):
    # undo out[PI[i]] = in[i]  ->  in[i] = out[PI[i]]
    return bytes(chunk[PI[i]] for i in range(16))

T = bytes(v ^ _SBOX_MASK for v in _aes_sbox())


# The whitening cipher's round-key schedule: 15 keys x 16 bytes, one per
# round, with a 14th-round final sweep.  Fixed for a given libsigner build and
# identical across every app; it is not derived from any other input.
KB = bytes.fromhex(
    "43fc368804c8ed1b17e5c8f603002f469e8f7ca2b2713e088c3f18324e1bc304"
    "6d6ce7273cf15f697e41c2ca2814b8d9610c29c68628429b5f420ffc440c99ad"
    "a427a6a5cd83ac99e6973b069bd6d68aeae0c558399dd296338a883f22d344c7"
    "e4a5e9507c73109ccfb17ecf0132fd10ca650736a6ad80f5c0725d9fb7f44c0d"
    "de7183c8f757c6016db3ed9b39d445de9a69cd0b699118abfcb610611e170939"
    "e23bd37b4039402f78dff8e1145ee86a1942b77e2586fa808c65bfb4c727e3d8"
    "82758e3497199b4eba9336fafb988bc5fdffaa1e8d2c05cb541cef2ac66e59a7"
    "208b07e8e2c7c9f30d01aa5ca3cc74cc")

def _encrypt_chunk(chunk, WA, _kb=KB):
    """One forward chunk: 14 rounds + final sweep.  (chunk ^ WA is inside.)"""
    x = bytearray(a ^ b for a, b in zip(chunk, WA))
    for r in range(14):
        x = bytearray(v ^ _SBOX_MASK ^ _kb[16 * r + i]
                    for i, v in enumerate(x))
        x = bytearray(T[v] ^ _SBOX_MASK for v in x)
        x = bytearray(_shift_rows(bytes(x)))
        if r < 13:
            x = bytearray(_mix_chunk(bytes(x)))
    return bytes(v ^ _SBOX_MASK ^ _kb[224 + i] for i, v in enumerate(x))

def encrypt(record, header):
    """record: 144 B plaintext, header: 16 B IV -> whitened body (144 B)."""
    out = bytearray()
    wa = header
    for k in range(len(record) // 16):
        c = _encrypt_chunk(record[16 * k:16 * k + 16], wa)
        out += c
        wa = c
    return bytes(out)

# THE RECORD -- 144 bytes, assembled field by field, then encrypted
# ------------------------------------------------------------------------

# The record's fixed bytes.  Tag-delimited: a one-byte tag precedes each
# variable field.  The tags are sequential type codes:
#     2 -> 4 bytes (the seed)
#     3 -> 20 bytes (the cert, SHA-1 length)
#     4 -> 32 bytes (the block)
#     5 -> 32 bytes (sha256 of the empty string)
#     6 -> the tail
_MAGIC = bytes((1, 0, 8))          # the 3-byte record header
_TAG_SEED = 2
_TAG_CERT = 3
_TAG_BLOCK = 4
_TAG_SHA256 = 5
_TAIL_HEADER = bytes((6, 1, 7))    # opens the final 33-byte field
_FILL = 14                          # 0x0E: the fill byte, which is also the
                                    # length of each fill run that follows


def build_record(seed, head, claims, cert):
    """The 144-byte plaintext record.

    Tag-delimited: a one-byte tag precedes each variable field.  Everything
    outside the head and the block is fixed format -- verified identical
    across every genuine capture.
    """
    head, cert = bytes(head), bytes(cert)
    if len(head) != 16:
        raise ValueError("head must be 16 bytes, got %d" % len(head))
    if len(cert) != 20:
        raise ValueError("cert must be 20 bytes, got %d" % len(cert))
    rec = bytearray(144)
    rec[0:3] = _MAGIC
    rec[3:19] = head
    rec[19] = _TAG_SEED
    rec[20:24] = struct.pack(">I", seed)
    rec[24] = _TAG_CERT
    rec[25:45] = cert
    rec[45] = _TAG_BLOCK
    rec[46:78] = record_block(head, seed, claims, cert)
    rec[78] = _TAG_SHA256
    rec[79:111] = SHA0
    rec[111:114] = _TAIL_HEADER
    rec[114:128] = bytes(_FILL)                     # zero fill
    rec[128:130] = bytes(2)
    rec[130:144] = bytes([_FILL]) * _FILL           # 14 x 0x0E
    return bytes(rec)


def sign(second, seed, claims, d9, head=None):
    """The 192-byte signature.  Pure: (second, seed, claims, cert, head)."""
    head16 = head16_for(seed, head)
    record = build_record(seed, head16, claims, d9)
    header = make_header(int(second))
    body = encrypt(record, header)
    return header + body + record_digest(body)


def sign_request(params, kind, campaign_data, head=None, second=None,
                 seed=None):
    """Sign one request. -> (authorization_header_value, blob_192B)

    Send the first; the second is the raw bytes, for callers that want them.
    A pure function -- nothing is remembered between calls.

    campaign_data keys that reach the signature: cert_sha1 (required),
    client_sdk (Flutter apps use "flutter5.8.0@android5.8.0"), adj_signing_id,
    headers_id, native_version, adj_verification, and optionally head_phase.
    """
    c = campaign_data
    val = dict(params)
    val.update({"activity_kind": kind,
                "client_sdk": c.get("client_sdk", "android5.7.0"),
                "adj_signing_id": c.get("adj_signing_id", "1500000"),
                "headers_id": c.get("headers_id", "10"),
                "native_version": c.get("native_version", "5.0.0"),
                "adj_verification": c.get("adj_verification", "")})
    second = int(second if second is not None else time.time())
    seed = int.from_bytes(os.urandom(4), "big") if seed is None else seed
    if not c.get("cert_sha1"):
        raise ValueError("campaign_data needs a cert_sha1")
    padded, unpadded_len = claims_padded(val, kind)
    # the block law hashes the claims UNPADDED: strip the NUL padding back off
    blob = sign(second, seed, padded[:unpadded_len],
                bytes.fromhex(c["cert_sha1"]),
                head or c.get("head_phase") or HEAD_PHASE_DEFAULT)
    return authorization_header(blob, campaign_data), blob



# ------------------------------------------------------------------------

def authorization_header(blob, campaign_data):
    """The envelope -> the Authorization header value.

    The server does not verify this envelope, but it must be well formed.
    """
    c = campaign_data
    return ('Signature signature="%s",adj_signing_id="%s",algorithm="adj9",'
            'headers_id="%s",native_version="%s",adj_verification="%s"'
            % (base64.b64encode(blob).decode(),
               c.get("adj_signing_id", "1500000"),
               c.get("headers_id", "10"),
               c.get("native_version", "5.0.0"),
               c.get("adj_verification", "")))
