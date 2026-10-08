"""adj9_pure_py27.py -- the Adjust adj9 signature, Python 2.7.

Generated from adj9_pure.py by make_py27.py.  Same algorithm, same
bytes; only the syntax is 2.7.  Do not edit by hand -- re-run the
generator and copy any change made to adj9_pure.py.

The Adjust adj9 signature in pure Python.  No VM.

    blob = header(16) || whitened_record(144) || digest(32)

  header     bionic rand() seeded by the signing second alone: 310 warm-up
             draws, then eight draws XORed in pairs, big-endian.
  record     144 bytes: the head comes from the seed, the request fields form
             the claims string, record[46:78) is SHA-256 chained from IV2 over
             cert || 00 08 || head || LE32(seed) || sha256("") || 01 00*16 ||
             claims.  Whitening: 14-round SPN, CBC from the header as IV, the
             AES S-box masked by 0x55 with AES ShiftRows/MixColumns and a
             recorded round-key schedule KB.  Digest: a two-pass SHA-256 MAC,
             not standard HMAC -- the pad is hashed twice.

  RECORDED   IV2, K, KB: cryptographically random VM immediates with no
  generating rule.  Everything else is derived -- SHA-256 constants from cube
  roots of primes, the S-box from its definition, the linear layer from GF(2^8)
  arithmetic.  Byte-exact against the VM and every genuine capture.

  USE        headers["Authorization"] = S.sign_request(fields, "click",
                                                       campaign_data,
                                                       second=sec)
  The campaign is PASSED IN -- the AutoLabs nested layout: top-level
  cert_sha1 / adj_verification / head_phase and an `adjust` sub-dict with
  app_token / sdk.  Omitted, it falls back to the module global
  adj9_pure.campaign_data (the offline gates set the global and call
  without the argument).  sign_request builds the claims string (the
  claims law below), signs and returns ONLY the Authorization header
  value.  sign() is the raw 192-byte core: sign(second, seed, claims,
  cert, head).
"""
import base64, hashlib, os, struct, time

SHA0 = hashlib.sha256(b"").digest()
_MASK32 = (1 << 32) - 1

# -- the d0 head phase: the one observed (not derived) input ------------------
# The selector prefix of the region law.  It does not affect attribution, so
# one value serves every app; pass head_phase= only to reproduce a captured
# signature.  Per-BUILD, not per-app -- see verify_head_prefix.py.
HEAD_PHASE_DEFAULT = (0x2B,)      # 43; the generated cycle 0x40|(i&7) follows

# Fallback only: sign_request takes the campaign as its third argument.
# The offline gates still set it once and call without the argument:
#     adj9_pure.campaign_data = campaign_data
campaign_data = None

# -- the claims law: which request fields are signed, in what order -----------
# One law covers every SDK generation: sorted profile, then the pinned
# adj_signing_id, then sorted tail, then block2 -- a key only when the map
# carries it non-empty.  mcc/mnc ARE signed when the device has a SIM
# (declic + penti 8 Sep captures, 4/4 block rebuilds); the RE device was
# SIM-less, which is why the law missed them until 2026-10-03.
PROFILE = ('adj_verification android_uuid api_level app_token app_version '
           'country created_at device_name device_type environment gps_adid '
           'gps_adid_src hardware_name installed_at mcc mnc os_build os_name '
           'os_version package_name push_token').split()
EVENT_EXTRA = 'event_count event_token partner_params'.split()
ATTR_DROP = 'hardware_name installed_at os_build'.split()
_GROUPS = {
    'session': (PROFILE + ['initiating_package_name'],
                ('session_count session_length store_name_from_system '
                 'subsession_count time_spent tracking_enabled '
                 'updated_at').split()),
    'click': (PROFILE + ('click_time click_time_server google_play_instant '
                         'install_begin_time install_begin_time_server '
                         'install_version referrer referrer_api').split(),
              ('session_count session_length source subsession_count '
               'time_spent tracking_enabled updated_at').split()),
    'attribution': ([k for k in PROFILE if k not in ATTR_DROP]
                    + ['initiated_by'], ['tracking_enabled']),
    'event': (PROFILE + EVENT_EXTRA,
              ('seq session_count session_length subsession_count time_spent '
               'tracking_enabled').split()),
    'info': (PROFILE, ['source', 'tracking_enabled']),
}
BLOCK2 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']
PIN = 'adj_signing_id'

def claim_key_order(val, kind):
    """Emission order; only keys the map actually carries are emitted."""
    profile, tail = _GROUPS[kind]
    keys = [k for k in sorted(profile) if val.get(k)]
    keys.append(PIN)                      # emitted pinned, read or not
    keys += [k for k in sorted(tail) if val.get(k)]
    return keys + [k for k in BLOCK2 if val.get(k)]

def claims_padded(val, kind):
    """(claims NUL-padded to a 4-byte multiple, unpadded length); the block
    hashes the claims UNPADDED."""
    raw = ''.join(val[k] for k in claim_key_order(val, kind)).encode('latin1')
    return raw + b"\x00" * (-len(raw) % 4), len(raw)

claims_padded_58 = claims_padded       # one law; the name old callers use

# -- the header: 16 bytes, a pure function of the signing second --------------
_M, _A = (1 << 31) - 1, 7 ** 5         # MINSTD: Mersenne prime modulus, 7**5
_Q, _R = _M // _A, _M % _A              # the Schrage split: 127773, 2836
_RAND0 = 123459876                      # rand()'s zero-state default, 0x075BD924

def _schrage(prev):
    """One Lehmer step; division must TRUNCATE toward zero, not floor."""
    if prev >= 0:
        hi, lo = divmod(prev, _Q)
    else:
        hi = -((-prev) // _Q)
        lo = prev - hi * _Q
    y = lo * _A - hi * _R
    return y + _M if y < 0 else y

def make_header(unix_sec):
    """bionic rand() -- MINSTD in Schrage's form, 31 state words, taps
    r[3]+r[0] -- seeded with the second; 310 warm-up draws discarded, then
    eight draws XORed in pairs.  rand() never starts from zero."""
    s = unix_sec & _MASK32 or 1
    st = [s if s < _M else s - (1 << 32)] + [0] * 30    # signed 31-bit words
    for i in range(1, 31):
        st[i] = _schrage(st[i - 1])
    d = []
    for k in range(310 + 8):
        f, b = (3 + k) % 31, k % 31
        v = (st[f] + st[b]) & _MASK32
        st[f] = v if v < _M else v - (1 << 32)
        if k >= 310:
            d.append(v >> 1)
    return b"".join(struct.pack(">I", d[2 * i] ^ d[2 * i + 1])
                    for i in range(4))

# -- the region: the 16-byte head, from the 32-bit seed -----------------------

def region_head(seed, phase=None):
    """24 Lehmer draws drive a 16-slot shuffle (slot i is filled with i, not
    textbook Fisher-Yates); one bit is forced on per halfword; a 16x16 bit
    transpose; then the eight selector halfwords fold halfwords 8..15 by XOR,
    selector s taking the halfwords whose bits are set in (s << 1) + 3.  Past
    the 1-2 byte `phase` prefix the selectors are 0x40 | (i & 7)."""
    ph = HEAD_PHASE_DEFAULT if phase is None else tuple(phase)
    state = seed & _MASK32
    perm = [0] * 16
    for i in range(16):
        state = _schrage(state or _RAND0)
        perm[i], perm[state % (i + 1)] = perm[state % (i + 1)], i
    pre = []
    for i in range(16):
        if i % 2 == 0:
            state = _schrage(state or _RAND0)
        v = state >> 16 if i % 2 == 0 else state
        pos = 15 - perm[i]
        pre.append((v & ((1 << pos) - 1)) | (1 << pos))
    pre = [sum(((pre[i] >> (15 - j)) & 1) << (15 - i) for i in range(16))
           for j in range(16)]
    src, out = pre[8:16], b""
    for a in range(8):
        mask = ((ph[a] if a < len(ph) else 0x40 | (a & 7)) << 1) + 3
        v = 0
        for bit in range(8):
            if (mask >> bit) & 1:
                v ^= src[7 - bit]
        out += struct.pack(">H", v)
    return out

head16_for = region_head           # the name the gates and run_install use

# -- SHA-256: the standard compression (hashlib cannot start from a custom IV,
# -- which the block law needs) ------------------------------------------------

def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK32

def _sha256_block(st, blk):
    w = list(blk)
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
        s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK32)
    a, b, c, d, e, f, g, h = st
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        t1 = (h + S1 + (g ^ (e & (f ^ g))) + _K256[i] + w[i]) & _MASK32
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        t2 = S0 + ((a & b) ^ (a & c) ^ (b & c))
        h, g, f, e = g, f, e, (d + t1) & _MASK32
        d, c, b, a = c, b, a, (t1 + t2) & _MASK32
    return [(x + y) & _MASK32 for x, y in zip(st, (a, b, c, d, e, f, g, h))]

def _primes(n):
    out, i = [], 2
    while len(out) < n:
        if all(i % p for p in out if p * p <= i):
            out.append(i)
        i += 1
    return out

def _frac_cbrt(p):
    """floor(frac(cbrt(p)) * 2**32), in exact integers -- no floats."""
    k = 0
    while (k + 1) ** 3 <= p:
        k += 1
    lo, hi, target, base = 0, 1 << 32, p << 96, k << 32
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if (base + mid) ** 3 <= target:
            lo = mid
        else:
            hi = mid - 1
    return lo

_K256 = tuple(_frac_cbrt(p) for p in _primes(64))   # the FIPS 180-4 constants

# -- the block: record[46:78], SHA-256 chained from IV2, not the standard IV ---
_BLK_IV2 = bytearray.fromhex("eba2c4350f4002dc9fa8dac5127035ba"
                         "7a30ed9323473054bbe3cd00f1355ea5")

def record_block(head, seed, claims, cert):
    """SHA256-IV2(cert || 00 08 || head || LE32(seed) || sha256("") ||
    01 00*16 || claims) -- standard padding and constants otherwise."""
    msg = (cert + b"\x00\x08" + head + struct.pack("<I", seed)
           + SHA0 + b"\x01" + b"\x00" * 16 + claims)
    st = list(struct.unpack(">8I", _BLK_IV2))
    m = (msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64)
         + struct.pack(">Q", len(msg) * 8))
    for i in range(0, len(m), 64):
        st = _sha256_block(st, list(struct.unpack(">16I", m[i:i + 64])))
    return struct.pack(">8I", *st)

# -- the digest: blob[160:192], a two-pass SHA-256 MAC -------------------------
_DIG_K = bytearray.fromhex("690f60944dddd9847db55cd7d2d576b3"
                       "0451723fbcfa92df62b55f6fec60f2de")

def record_digest(body):
    """Not standard HMAC: the pad block is hashed a second time after the
    keyed block.  sha256((K^opad)||opad||sha256((K^ipad)||ipad||body))."""
    ki = bytearray(a ^ 0x36 for a in _DIG_K)
    ko = bytearray(a ^ 0x5C for a in _DIG_K)
    inner = hashlib.sha256(ki + b"\x36" * 32 + body).digest()
    return hashlib.sha256(ko + b"\x5c" * 32 + inner).digest()

# -- the whitening cipher: 14-round SPN, CBC from the header as IV -------------
# AES's S-box (masked by 0x55), ShiftRows and MixColumns; only the round-key
# schedule KB is recorded -- it is not an AES expansion (verify_aes256_claim).
_SBOX_MASK = 0x55

def _gmul(a, b):
    """Multiply in GF(2^8) mod x^8+x^4+x^3+x+1 (0x11B)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return p

def _gpow(a, e):
    r, base = 1, a
    while e:
        if e & 1:
            r = _gmul(r, base)
        base = _gmul(base, base)
        e >>= 1
    return r

def _rotl8(x, n):
    return ((x << (n % 8)) | (x >> (8 - n % 8))) & 0xFF

def _aes_sbox():
    """The AES S-box from its definition: affine(x^-1) ^ 0x63."""
    out = []
    for v in range(256):
        inv = 0 if v == 0 else _gpow(v, 254)
        out.append(inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2)
                   ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63)
    return bytearray(out)

# T = the AES S-box XOR 0x55.  The round XORs 0x55 either side of the lookup,
# so the two cancel and the effective map is plain AES.  Do not fold the
# constant in; it changes the cipher.
T = bytearray(v ^ _SBOX_MASK for v in _aes_sbox())

# ShiftRows: byte i is row i%4, column i//4; row r rotates left by r.
PI = [4 * (((i // 4) - (i % 4)) % 4) + (i % 4) for i in range(16)]

def _shift_rows(chunk):
    out = bytearray(16)
    for i in range(16):
        out[PI[i]] = chunk[i]
    return bytearray(out)

def mix_columns(word):
    """AES MixColumns, little-endian 32-bit word:
    y_b = 2*x_b ^ 3*x_(b+1) ^ x_(b+2) ^ x_(b+3)."""
    b = [(word >> 8 * i) & 0xFF for i in range(4)]
    out = 0
    for i in range(4):
        out |= (_gmul(2, b[i]) ^ _gmul(3, b[(i + 1) % 4])
                ^ b[(i + 2) % 4] ^ b[(i + 3) % 4]) << 8 * i
    return out

def _mix_chunk(chunk):
    return b"".join(struct.pack("<I",
                                mix_columns(struct.unpack_from("<I", chunk,
                                                               4 * i)[0]))
                    for i in range(4))

KB = bytearray.fromhex(
    "43fc368804c8ed1b17e5c8f603002f469e8f7ca2b2713e088c3f18324e1bc304"
    "6d6ce7273cf15f697e41c2ca2814b8d9610c29c68628429b5f420ffc440c99ad"
    "a427a6a5cd83ac99e6973b069bd6d68aeae0c558399dd296338a883f22d344c7"
    "e4a5e9507c73109ccfb17ecf0132fd10ca650736a6ad80f5c0725d9fb7f44c0d"
    "de7183c8f757c6016db3ed9b39d445de9a69cd0b699118abfcb610611e170939"
    "e23bd37b4039402f78dff8e1145ee86a1942b77e2586fa808c65bfb4c727e3d8"
    "82758e3497199b4eba9336fafb988bc5fdffaa1e8d2c05cb541cef2ac66e59a7"
    "208b07e8e2c7c9f30d01aa5ca3cc74cc")

def _encrypt_chunk(chunk, wa):
    """One chunk, CBC: (chunk ^ wa) through 14 rounds + the final sweep.
    Round r: AddRoundKey (KB ^ 0x55), SubBytes (T, unmasked by the trailing
    0x55), ShiftRows, and MixColumns on every round but the 14th."""
    x = bytearray(a ^ b for a, b in zip(bytearray(chunk),
                                     bytearray(wa)))
    for r in range(14):
        x = bytearray(v ^ _SBOX_MASK ^ KB[16 * r + i] for i, v in enumerate(x))
        x = bytearray(T[v] ^ _SBOX_MASK for v in x)
        x = _shift_rows(x)
        if r < 13:
            x = bytearray(_mix_chunk(x))
    return bytearray(v ^ _SBOX_MASK ^ KB[224 + i] for i, v in enumerate(x))

def encrypt(record, header):
    """144 B plaintext + 16 B IV -> the whitened body."""
    out, wa = b"", header
    for k in range(len(record) // 16):
        c = _encrypt_chunk(record[16 * k:16 * k + 16], wa)
        out += c
        wa = c
    return out

# -- the record: 144 bytes, tag-delimited; tags are sequential type codes ------
_MAGIC = bytearray((1, 0, 8))
_TAIL_HEADER = bytearray((6, 1, 7))     # opens the final 33-byte field
_FILL = 14                          # 0x0E: the fill byte and the run length

def build_record(seed, head, claims, cert):
    """Everything outside the head and the block is fixed format."""
    rec = bytearray(144)
    rec[0:3] = _MAGIC
    rec[3:19] = head
    rec[19] = 2                     # tag: 4-byte seed
    rec[20:24] = struct.pack(">I", seed)
    rec[24] = 3                     # tag: 20-byte cert
    rec[25:45] = cert
    rec[45] = 4                     # tag: 32-byte block
    rec[46:78] = record_block(head, seed, claims, cert)
    rec[78] = 5                     # tag: 32-byte sha256("")
    rec[79:111] = SHA0
    rec[111:114] = _TAIL_HEADER
    rec[130:144] = bytearray([_FILL]) * _FILL       # 114:130 stays zero
    return bytearray(rec)

# -- the signature -------------------------------------------------------------

def sign(second, seed, claims, cert, head=None):
    """The 192-byte signature: header || whitened record || digest."""
    head16 = region_head(seed, head)
    record = build_record(seed, head16, claims, cert)
    header = make_header(int(second))
    body = encrypt(record, header)
    return header + body + record_digest(body)

def sign_request(fields, kind, campaign=None, second=None, seed=None, head=None):
    """Sign one request and return the Authorization header VALUE (a string,
    nothing else).  The campaign is passed in:

        headers["Authorization"] = sign_request(fields, "click", campaign_data,
                                                second=sec)

    Omitted, it falls back to the module-global adj9_pure.campaign_data (the
    offline gates set the global and call without the argument).  The
    campaign is the AutoLabs nested layout: top-level cert_sha1 (required),
    adj_verification and optionally head_phase, and an `adjust` sub-dict
    with app_token / sdk; adj_signing_id, headers_id and native_version read
    top-level with the defaults below.
    """
    c = campaign if campaign is not None else campaign_data
    if c is None:
        raise ValueError("sign_request needs a campaign (pass it in, or set "
                         "adj9_pure.campaign_data)")
    val = dict(fields)
    val.update({"activity_kind": kind,
                # the SIGNED client_sdk must be the app's own SDK string -- it
                # sits under adjust.sdk in the AutoLabs-format campaign dicts;
                # the old android5.7.0 fallback leaked penti's value into
                # every other app and their installs silently went Organic
                "client_sdk": (c.get("client_sdk")
                               or (c.get("adjust") or {}).get("sdk")
                               or "android5.7.0"),
                "adj_signing_id": c.get("adj_signing_id", "1500000"),
                "headers_id": c.get("headers_id", "10"),
                "native_version": c.get("native_version", "5.0.0"),
                "adj_verification": c.get("adj_verification", "")})
    second = int(second if second is not None else time.time())
    seed = struct.unpack(">I", os.urandom(4))[0] if seed is None else seed
    padded, n = claims_padded(val, kind)
    blob = sign(second, seed, padded[:n], bytearray.fromhex(c["cert_sha1"]),
                head or c.get("head_phase") or HEAD_PHASE_DEFAULT)
    return authorization_header(blob, c)

def authorization_header(blob, campaign_data):
    """The envelope.  The server does not verify it, but it must be formed."""
    c = campaign_data
    return ('Signature signature="%s",adj_signing_id="%s",algorithm="adj9",'
            'headers_id="%s",native_version="%s",adj_verification="%s"'
            % (base64.b64encode(blob).decode(),
               c.get("adj_signing_id", "1500000"),
               c.get("headers_id", "10"),
               c.get("native_version", "5.0.0"),
               c.get("adj_verification", "")))
