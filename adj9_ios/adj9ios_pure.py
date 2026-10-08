"""adj9ios_pure.py — the SELF-CONTAINED adj9-iOS pure signer (SDK ios5.8.0 /
signature native 5.0.0), verified byte-exact against 5 genuine capture blobs.

  sign_request(fields, kind, second=None, nonce4=None) -> (blob192, auth_header)
  make_adj_verification(os_name="ios")  -> the adj_verification value

Law summary:
  header   = MINSTD: x=(second mod 2^31-1, 0->1); 8 draws 16807*x mod p;
             w_i = d[2i]^d[2i+1]; BE x4                  (iOS generator)
  record   = magic 01 00 08 | d0head(16, phase (0x40,)) | S(BE32) | 03 | D9(20 zero B)
             | 04 | BLOCK(32) | 05 | sha256("") | 06 | 02 | 07 | device_name(16) | 0e*14
  BLOCK    = sha256_iv2( D9 || 00 08 || head16=record[3:19] || LE32(S) || sha256("")
                         || TAIL(17B: 02||device_name||00*6) || claims )
  claims   = adj_verification || pool keys < "session_count" (95-key pool order)
             || "1500000" || pool keys >= "session_count"
             || activity_kind, client_sdk, headers_id, native_version
  whitening= 14-round AES-derived SPN (inverse ShiftRows, custom KB), CBC from header
  digest   = sha256((K^opad)||opad||sha256((K^ipad)||ipad||body))

Python 2/3 compatible (see adj9ios_pure_py27.py).
"""

import json, struct, hashlib, os, time, sys, base64


# ---- PART 0: shared math + key material (the native's own values) ----

_MINSTD_M = (1 << 31) - 1                # the Mersenne prime 2^31 - 1

_MINSTD_A = 7 ** 5                       # 16807, the MINSTD multiplier

_MINSTD_Q = _MINSTD_M // _MINSTD_A       # Schrage q  (127773)

_MINSTD_R = _MINSTD_M % _MINSTD_A        # Schrage r  (2836)

_MASK16 = (1 << 16) - 1                  # halfword mask (d0 selectors)

_MASK32 = (1 << 32) - 1                  # word mask

KB_HEX = ("16a963dd519db84e42b09da356557a13cbda29f7e7246b5dd96a4d671b4e9651"
          "3839b27269a40a3c2b14979f7d41ed8c34597c93d37d17ce0a175aa91159ccf8"
          "f172f3f098d6f9ccb3c26e53ce8383dfbfb5900d6cc887c366dfdd6a77861192"
          "b1f0bc05292645c99ae42b9a5467a8459f305263f3f8d5a0952708cae2a11958"
          "8b24d69da202935438e6b8ce6c81108bcf3c985e3cc44dfea9e345344b425c6c"
          "b76e862e156c157a2d8aadb4410bbd3f4c17e22b70d3afd5d930eae19272b68d"
          "d720db61c24cce1befc663afaecdde90a8aaff4bd879509e0149ba7f933b0cf2"
          "75de52bdb7929ca65854ff09f6992199")

KB = bytes.fromhex(KB_HEX)          # 15 x 16-B round keys; KB[224:240] is

IV2 = bytes.fromhex("eba2c4350f4002dc9fa8dac5127035ba"
                    "7a30ed9323473054bbe3cd00f1355ea5")  # block-hash IV

DK = bytes.fromhex("690f60944dddd9847db55cd7d2d576b3"
                   "0451723fbcfa92df62b55f6fec60f2de")  # digest MAC key


# ---- PART 0b: iOS aliases ----

MINSTD_P = _MINSTD_M
MINSTD_A = _MINSTD_A
HEAD_FIRST = (0x40,)      # iOS d0 selector phase (the pure cycle, index 0)
IOS_HEAD_PHASE = (0x40,)
ADJ_SIGNING_ID = '1500000'


# ---- PART 1: the iOS header (MINSTD, pair-XOR, BE) ----

def minstd_state(unix_sec):
    x = unix_sec % MINSTD_P
    return 1 if x == 0 else x

def minstd_draws(unix_sec, n=8):
    x = minstd_state(unix_sec)
    out = []
    for _ in range(n):
        x = (MINSTD_A * x) % MINSTD_P
        out.append(x)
    return out

def make_ios_header(unix_sec):
    """The 16-byte header (whitening IV) an iOS device mints for a second."""
    d = minstd_draws(unix_sec, 8)
    words = [(d[2 * i] ^ d[2 * i + 1]) & 0xFFFFFFFF for i in range(4)]
    return b"".join(struct.pack(">I", w) for w in words)


# ---- PART 2: seed S -> d0 head (phase (0x40,) on iOS) ----

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

def head_words(d0w):
    """d0[0..3] -> record[3:19): each 32-bit word 16-bit-swapped, LE-packed."""
    return b"".join(struct.pack("<I", ((w & 0xFFFF) << 16) | (w >> 16))
                    for w in d0w[:4])

def head16_for(S, head=None):
    """The 16-byte d0 head the record carries for seed S and a selector
    phase."""
    return head_words(_d0_words(_d4_words(S), head=head))


# ---- PART 4: sha256 chained from the custom IV2 (block hash) ----

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

SHA0 = hashlib.sha256(b'').digest()


# ---- PART 5: the 14-round SPN whitening (AES-derived, custom KB) ----

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

def _apply_tab(tab, x):
    return (tab[0][x & 0xFF] ^ tab[1][(x >> 8) & 0xFF]
            ^ tab[2][(x >> 16) & 0xFF] ^ tab[3][(x >> 24) & 0xFF])

def _F(chunk):
    """The linear mix on a 16-B chunk: 4 little-endian words through F."""
    return b"".join(_apply_tab(_F_TAB,
                               int.from_bytes(chunk[4 * b:4 * b + 4],
                                              "little")).to_bytes(4, "little")
                    for b in range(4))

def _pi1(chunk):
    """SHIFTROWS: out[_PI[i]] = in[i]."""
    out = bytearray(16)
    for i, c in enumerate(chunk):
        out[_PI[i]] = c
    return bytes(out)

def _derive_pi():
    """The SHIFTROWS permutation: the 16-B chunk is a 4x4 matrix (index
    i = 4*col + row) and each row r is rotated right by r."""
    pi = [0] * 16
    for i in range(16):
        j, r = divmod(i, 4)
        pi[i] = 4 * ((j + (0, 3, 2, 1)[r]) % 4) + r
    return pi

SBOX, F_ROWS = _derive_tables()

_PI = _derive_pi()

_F_TAB = _byte_tables(F_ROWS)

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


# ---- PART 6: the double-padded digest MAC ----

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


# ---- PART 3: the SOLVED iOS claims law (pool order, session_count split) ----

POOL_95 = ['ad_impressions_count', 'ad_revenue_network', 'ad_revenue_placement', 'ad_revenue_unit', 'adgroup', 'android_id', 'android_uuid', 'api_level', 'app_secret', 'app_token', 'app_version', 'app_version_short', 'att_status', 'bundle_id', 'callback_params', 'campaign', 'click_time', 'click_time_server', 'country', 'created_at', 'creative', 'currency', 'deduplication_id', 'default_tracker', 'details', 'device_known', 'device_name', 'device_type', 'environment', 'event_callback_id', 'event_count', 'event_token', 'external_device_id', 'fb_anon_id', 'fb_id', 'ff_app_set_id_disabled', 'ff_att_disabled', 'ff_idfv_disabled', 'ff_odm_enabled', 'fire_adid', 'fire_tracking_enabled', 'found_location', 'google_play_instant', 'gps_adid', 'gps_adid_src', 'granular_third_party_sharing_options', 'hardware_name', 'idfa', 'idfv', 'initiated_by', 'initiating_package_name', 'install_begin_time', 'install_begin_time_server', 'install_version', 'installed_at', 'last_skan_update', 'mcc', 'measurement', 'mnc', 'needs_cost', 'odm_info', 'order_id', 'originating_package_name', 'os_build', 'os_name', 'os_version', 'package_name', 'params', 'partner_params', 'partner_sharing_settings', 'payload', 'primary_dedupe_token', 'purchase_time', 'push_token', 'referrer', 'referrer_api', 'reftag', 'revenue', 'sales_region', 'secondary_dedupe_token', 'seq', 'session_count', 'session_length', 'sharing', 'skadn_registered_at', 'source', 'started_at', 'store_app_id_from_client', 'store_name_from_client', 'store_name_from_system', 'subsession_count', 'time_spent', 'tracker', 'tracking_enabled', 'updated_at']

SPLIT = POOL_95.index('session_count')

BLOCK2 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']

INJECTED = {
    'adj_signing_id': '1500000',
    'client_sdk': 'ios5.8.0',
    'headers_id': '10',
    'native_version': '5.0.0',
}

def signing_map(wire_params, activity_kind, adj_verification, inj=None):
    inj = inj or INJECTED
    m = dict(wire_params)
    m["adj_signing_id"] = inj["adj_signing_id"]
    m["client_sdk"] = inj["client_sdk"]
    m["headers_id"] = inj["headers_id"]
    m["native_version"] = inj["native_version"]
    m["activity_kind"] = activity_kind
    m["adj_verification"] = adj_verification
    return m

def build_claims(wire_params, activity_kind, adj_verification, inj=None):
    """The claims string (str) for one request.  inj: the injected-constants
    dict (defaults to INJECTED); pass the campaign's own values when signing
    for a specific c["adjust"] block."""
    m = signing_map(wire_params, activity_kind, adj_verification, inj)
    prof = [k for k in POOL_95[:SPLIT] if m.get(k)]
    tail = [k for k in POOL_95[SPLIT:] if m.get(k)]
    keys = (["adj_verification"] + prof + ["adj_signing_id"] + tail + BLOCK2)
    return "".join(m[k] for k in keys), keys

def block_message(record, claims):
    """BLOCK pre-image from the unsealed 144-B record + claims (bytes/str)."""
    if isinstance(claims, str):
        claims = claims.encode("latin-1")
    return (record[25:45] + b"\x00\x08" + record[3:19]
            + record[20:24][::-1]                     # BE32 storage -> LE32 in msg
            + SHA0 + record[112:113] + record[114:130] + claims)

def predict_block(record, claims):
    return sha256_iv2(block_message(record, claims))

ADJ_V_KEY = b"Quoh8uafohgh7CahM2h"          # 19-byte effective pad (cycled)

def make_adj_verification(os_name="ios", key=ADJ_V_KEY):
    plain = json.dumps({"os_name": os_name}, separators=(",", ":")).encode()
    return base64.b64encode(bytes(b ^ key[i % len(key)]
                                  for i, b in enumerate(plain))).decode()


# ---- PART 7: the iOS record builder + mint ----

def ios_auth_header(blob, os_name="ios", signing_id=ADJ_SIGNING_ID,
                    headers_id="10", native_version="5.0.0"):
    return ('Signature signature="%s",adj_signing_id="%s",algorithm="adj9",'
            'headers_id="%s",native_version="%s",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), signing_id, headers_id,
               native_version, make_adj_verification(os_name)))

def build_record_ios(S, head16, claims, device_name="iPhone13,2",
                     variant=0x02, d9=b"\x00" * 20):
    """The 144-B iOS record.  Android = build_record(S, head16, claims, d9);
    the three iOS deviations are the variant byte, the device-name field and
    the all-zero cert."""
    head16 = bytes(head16)
    d9 = bytes(d9)
    if len(head16) != 16:
        raise ValueError("head16 must be 16 bytes")
    if len(d9) != 20:
        raise ValueError("d9 must be 20 bytes")
    dev = device_name.encode("latin1")[:16]
    dev = dev + b"\x00" * (16 - len(dev))
    block = predict_block_ios(S, head16, claims, d9, variant, dev)
    out = bytearray(144)
    out[0:3] = b"\x01\x00\x08"
    out[3:19] = head16
    out[19] = 0x02
    out[20:24] = struct.pack(">I", S & 0xFFFFFFFF)
    out[24] = 0x03
    out[25:45] = d9
    out[45] = 0x04
    out[46:78] = block
    out[78] = 0x05
    out[79:111] = SHA0
    out[111:114] = b"\x06" + bytes([variant]) + b"\x07"
    out[114:130] = dev
    out[130:144] = b"\x0e" * 14
    return bytes(out)

def block_message_ios(S, head16, claims, d9, variant, dev):
    """sha256-IV2 message: D9 || 00 08 || head16 || LE32(S) || sha256("") ||
    variant || device_field(16) || claims  (the Android-verified recipe with
    the record-sourced iOS descriptor-6/7 payloads)."""
    return (bytes(d9) + b"\x00\x08" + bytes(head16)
            + struct.pack("<I", S & 0xFFFFFFFF) + SHA0
            + bytes([variant]) + bytes(dev) + bytes(claims))

def predict_block_ios(S, head16, claims, d9, variant=0x02,
                      dev=b"iPhone13,2" + b"\x00" * 6):
    return sha256_iv2(block_message_ios(S, head16, claims, d9, variant,
                                           dev))

def _mint_ios(kind, params, unix_sec=None, S=None, device_name="iPhone13,2",
             os_name="ios", claims=None, head=IOS_HEAD_PHASE, variant=0x02,
             d9=b"\x00" * 20, client_sdk=None, signing_id=ADJ_SIGNING_ID):
    """Mint one 192-byte adj9 signature for an iOS request.

    kind   : session | click | attribution | event
    params : dict of the request's decoded wire fields
    unix_sec : signing second (default now) — seeds the MINSTD header
    S      : 32-bit fill seed (default random)
    claims : explicit claims payload (bytes/str) — overrides the law
    returns (blob192, auth_header_string)
    """
    if kind not in ("session", "click", "attribution", "event"):
        raise ValueError("bad kind %r" % kind)
    second = int(unix_sec if unix_sec is not None else time.time())
    seed = int.from_bytes(os.urandom(4), "big") if S is None else int(S)
    cb = (claims.encode("latin1") if isinstance(claims, str)
          else bytes(claims) if claims is not None
          else build_claims_ios(params, kind, signing_id=signing_id,
                                client_sdk=client_sdk))
    head16 = head16_for(seed, head)
    record = build_record_ios(seed, head16, cb, device_name=device_name,
                              variant=variant, d9=d9)
    header = make_ios_header(second)
    body = whiten_forward(record, header)
    blob = header + body + predict_digest(body)
    auth = ios_auth_header(blob, os_name=os_name, signing_id=signing_id)
    return blob, auth


# ---- PART 8: the ONE-CALL API (the adj9-Android pattern: the campaign dict
#      `c` comes from the runner; the signer owns every constant) ----
KINDS = ("session", "click", "event", "attribution")


def _adjust_block(c):
    return c["adjust"]


def _mint(fields, kind, c, second, nonce4):
    """The full mint: returns (blob192, auth_header).  Internal — the public
    entry is sign_request()."""
    adj = _adjust_block(c)
    adj_v = adj.get("adj_verification") or make_adj_verification("ios")
    inj = {"adj_signing_id": adj["adj_signing_id"],
           "client_sdk": adj["sdk"],
           "headers_id": adj["headers_id"],
           "native_version": adj["native_version"]}
    claims = build_claims(fields, kind, adj_v, inj)[0]
    if isinstance(claims, str):
        claims = claims.encode("latin1")
    p = dict(fields)
    p.setdefault("activity_kind", kind)
    head = tuple(c.get("head_phase", IOS_HEAD_PHASE))
    blob, _auth = _mint_ios(kind, p, unix_sec=second, S=int.from_bytes(nonce4, "big"), claims=claims,
                            device_name=c["device_name"], os_name=c.get("os_name", "ios"),
                            client_sdk=adj["sdk"], head=head)
    auth = ('Signature signature="%s",adj_signing_id="%s",algorithm="%s",'
            'headers_id="%s",native_version="%s",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), adj["adj_signing_id"],
               adj["algorithm"], adj["headers_id"], adj["native_version"],
               adj_v))
    return blob, auth


def sign_request(fields, kind, c, second=None, nonce4=None):
    """fields: the request's wire params (str->str, DECODED values).
    kind: session|click|event|attribution.
    c: the nested campaign dict — c["adjust"] carries {sdk, adj_signing_id,
    headers_id, algorithm, native_version, adj_verification}, and
    c["device_name"] / c["head_phase"] the record profile.
    second: signing second (default now).  nonce4: the 4-B seed S (default
    random, generated inside).  Returns the finished Authorization header."""
    if kind not in KINDS:
        raise ValueError("kind must be one of %r" % (KINDS,))
    if second is None:
        second = int(time.time())
    if nonce4 is None:
        nonce4 = os.urandom(4)
    _blob, auth = _mint(fields, kind, c, second, nonce4)
    return auth


# ---- PART 9: 5 genuine capture blobs frozen inside (byte-exact selftest) ----

GOLD_JSON = '[{"kind": "session", "second": 1791180941, "params": {"bundle_id": "com.penti.PentiApp", "primary_dedupe_token": "b2456983-e848-42be-ba88-58014d427717", "last_skan_update": "{\\"coarse_value\\":\\"low\\",\\"lock_window\\":false,\\"timestamp\\":\\"2026-10-05T09:15:41.744Z+0300\\",\\"source\\":\\"sdk\\",\\"conversion_value\\":0}", "app_version": "8", "foreground": "1", "installed_at": "2026-10-05T09:14:36.678Z+0300", "device_name": "iPhone12,1", "app_version_short": "2.35.0", "retry_count": "0", "needs_response_details": "1", "attribution_deeplink": "1", "skadn_registered_at": "2026-10-05T09:15:41.743Z+0300", "session_count": "1", "os_name": "ios", "send_in_background_enabled": "0", "enqueue_size": "0", "idfv": "76784475-D45B-4FC7-8107-D6C3C51584A8", "app_token": "jut9tib0eeps", "environment": "production", "os_version": "26.5", "sent_at": "2026-10-05T09:15:41.900Z+0300", "started_at": "2026-10-05T07:29:58.000Z+0300", "created_at": "2026-10-05T09:15:41.883Z+0300", "offline_mode_enabled": "0", "device_type": "iPhone", "att_status": "0"}, "nonce4": "f41e6b39", "blob_hex": "2a9bd1d575e0b9e16619295a57c94f2fffeac32f0a4a7ff1028b25f895fe5b80e98309811a6155b97eb2162d5b247a6e5a0ec9573f1a57eb85dbb23901e8167662f0749a488ae9bf85900284e0f31f87b9146c715d24bf29e72839ac62f61c1915fe94496f6a4b99f2f261f5d0eb0e18a10f05d91c0f9e4a218685eb3f8b0284d749157a290bd835d49467adcd8ab74530d9d6abeb0e3ccd0571e89c7121f4a13372acd1b1ad3adaa0c4e30ee781c756e15a8096694fcfb54a29824b049fa683", "adj_v": "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb", "head": [9]}, {"kind": "click", "second": 1791180942, "params": {"bundle_id": "com.penti.PentiApp", "source": "apple_ads", "primary_dedupe_token": "b2456983-e848-42be-ba88-58014d427717", "last_skan_update": "{\\"coarse_value\\":\\"low\\",\\"lock_window\\":false,\\"timestamp\\":\\"2026-10-05T09:15:41.744Z+0300\\",\\"source\\":\\"sdk\\",\\"conversion_value\\":0}", "app_version": "8", "foreground": "1", "installed_at": "2026-10-05T09:14:36.678Z+0300", "device_name": "iPhone12,1", "app_version_short": "2.35.0", "needs_response_details": "1", "attribution_deeplink": "1", "skadn_registered_at": "2026-10-05T09:15:41.743Z+0300", "session_count": "1", "os_name": "ios", "send_in_background_enabled": "0", "session_length": "0", "attribution_token": "CBdNbt5lrMjV54+CGb9HItWX6Kuc65HsWvZljNMkN4QF2/RQM04NZwK0toYyGAmk2wl1ftvjZ2Hrmyw4CqqzliwmQIrApOGOnwAAAVADAAAAywAAAIB7l2v21JU0PO0IC2COF2+t+8DLsLDrdJiQWlYUZLZxMzIYtaLsqlMBNwptHKQWNH4XU6qed8811mG+6cfNTQ163OF5H5RJEdujnk3vw+wsQWDZ3ZD+5X2pIB1IoyvYStbiM1EAXm9OJDCNR1hwAhUZWV2oDaSF+Hs4uMpnAPqAuwAAABFZLagF3UztS9X+hIuFws4mLgAAAJ8BCHGDCdLt83u/9z50kQRJZwyFZtoAAACGAQnxVsHISp0D4frWrGbsa13yasDIxtZf9e4f5bn+DAi7dosYjtOQr7IQmfuXpuEIINUv0IdJ0q11YSlt1bScH+MhrElA3UIOsxlzMqpzSnnW7xVjUnqPDX+4Hf6jKnlJQDN1cqKWhz2NZxNYuikBUZ0ChOZyGPapHAB+5njoIHXDWqqUzKYAAAAAAAAAAAAAAAAAAAABBEsTAQA=", "sent_at": "2026-10-05T09:15:42.044Z+0300", "environment": "production", "time_spent": "0", "app_token": "jut9tib0eeps", "os_version": "26.5", "subsession_count": "1", "started_at": "2026-10-05T07:29:58.000Z+0300", "idfv": "76784475-D45B-4FC7-8107-D6C3C51584A8", "created_at": "2026-10-05T09:15:42.037Z+0300", "offline_mode_enabled": "0", "device_type": "iPhone", "att_status": "0"}, "nonce4": "30e79d39", "blob_hex": "1bec683d49627ed1466cb487782646702e44a17e6fa21e28674d6af3b98d2b46807f4c26d6af1c0ad2568474e83cafb065162df9f466bac5596276bb964c3b96d57a2320bde2fff987ac4d522eb51f6eaf12bf6a78ef6334d9ad19fe914658891948e06285af96224ae948164426101a4e5beaa68fb045ca938c1dd70ef60bada97a1cb5f008779cb43bbbb2fa8844ac5066ec9f5b5be182dc74e215f26b6a14fbc21689881f1ecfd505a7dd2fec8c2c5aaef98b14587beea54cd521f2ac8d3b", "adj_v": "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb", "head": [9]}, {"kind": "attribution", "second": 1791180949, "params": {"bundle_id": "com.penti.PentiApp", "primary_dedupe_token": "b2456983-e848-42be-ba88-58014d427717", "initiated_by": "backend", "last_skan_update": "{\\"coarse_value\\":\\"low\\",\\"lock_window\\":false,\\"timestamp\\":\\"2026-10-05T09:15:44.420Z+0300\\",\\"source\\":\\"backend\\",\\"conversion_value\\":0}", "app_version": "8", "installed_at": "2026-10-05T09:14:36.678Z+0300", "device_name": "iPhone12,1", "app_version_short": "2.35.0", "needs_response_details": "1", "attribution_deeplink": "1", "skadn_registered_at": "2026-10-05T09:15:41.743Z+0300", "send_in_background_enabled": "0", "os_name": "ios", "sent_at": "2026-10-05T09:15:49.492Z+0300", "idfv": "76784475-D45B-4FC7-8107-D6C3C51584A8", "app_token": "jut9tib0eeps", "os_version": "26.5", "environment": "production", "started_at": "2026-10-05T07:29:58.000Z+0300", "created_at": "2026-10-05T09:15:49.488Z+0300", "device_type": "iPhone", "att_status": "0"}, "nonce4": "9be74ac8", "blob_hex": "21cf89044d7471fb67d044ec4ebd646502881871f1528e1e85db296c1de1e63390dcfd9078c26f22cc0ce4e8dcee42c253548251bf3aed88594555a2898d0db239e668a7443ebbd10c34a07feb7d0e99eec10ad6a1b864bf3b6b30120fcbc79585f267d041472669b6e225d8efd449ffcb15ea8316a7ecc141085f4cd6688d3f5761c3f7d85277242f101e23cdcdf43f3fc1dd5e6d7a5f701bbb692e9ce4128dc67b2ea9082defaae775e013e6c360712fb90d0475677bb00d548e0c1b981fe3", "adj_v": "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb", "head": [9]}]'

GOLD_VECTORS = json.loads(GOLD_JSON)


def self_test(verbose=True):
    ok = 0
    for v in GOLD_VECTORS:
        cvec = {"adjust": {"sdk": "ios5.8.0", "adj_signing_id": "1500000",
                           "headers_id": "10", "algorithm": "adj9",
                           "native_version": "5.0.0",
                           "adj_verification": v["adj_v"]},
                "device_name": "iPhone12,1", "os_name": "ios",
                "head_phase": list(v.get("head", (0x09,)))}
        auth = sign_request(v["params"], v["kind"], c=cvec,
                            second=v["second"],
                            nonce4=bytes.fromhex(v["nonce4"]))
        # the byte-exact proof: the returned header must embed the genuine blob
        want_blob = bytes.fromhex(v["blob_hex"])
        want_sig = base64.b64encode(want_blob).decode()
        good = ('signature="%s"' % want_sig) in auth
        ok += good
        if verbose:
            print("[PURE] %-12s second=%d %s" % (v["kind"], v["second"],
                  "BYTE-EXACT" if good else "MISMATCH"))
    if verbose:
        print("[PURE] self_test: %d/%d byte-exact vs genuine device blobs"
              % (ok, len(GOLD_VECTORS)))
    return ok == len(GOLD_VECTORS)


if __name__ == "__main__":
    sys.exit(0 if self_test() else 1)