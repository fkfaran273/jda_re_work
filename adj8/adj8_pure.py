"""adj8_pure.py -- the Adjust adj8 signature in pure Python.  No VM.

    blob = header(16) || AES-256-CBC record(128) || tag(32)

  header  bionic rand() seeded by the signing second: 310 warm-up draws,
          then eight draws XORed in pairs, big-endian.
  record  head from the 4-byte nonce, then nonce4 (raw), the cert SHA-1 and
          the block -- SHA-256 chained from IV2 over cert || 00 08 || head ||
          rev4(nonce4) || sha256("") || 01 || claims.  AES-256-CBC with the
          fixed key, IV = header; tag = HMAC-SHA256(DK38) over the body.

  RECORDED  DK38 and the AES key: lib immediates, no generating rule.
  Derived: head masks (131 step 2), IV2 (lib immediates XOR 3435973836), the
  AES S-box and schedule, the SHA-256 constants (cube roots of primes).
  Byte-exact on the genuine 3.67.0 device blobs (bevietnam_.saz) and
  server-proven non-organic (2026-10-04 replay + fresh-GAID install).

  USE    auth = sign_request(fields, "session", campaign_data, second=sec)
"""
import base64, hashlib, hmac, os, struct, time

SHA0 = hashlib.sha256(b"").digest()

# the two recorded lib immediates (no generating rule)
DK38 = bytes.fromhex("caab83444a2146392abb96b64230615529a770c63c163c1c7528673e0671728f")
AES_KEY = bytes.fromhex("ffb5e5f9c862b637d13351c292633e39965a3c2d037ed64dfff5388e11d80db3")

# -- the claims law: the native's pool in emission order; a key only when the
# -- map carries it non-empty; values concatenated bare.  adj_signing_id pins
# -- after "main" (right after package_name); headers_id + native_version
# -- close the string.
CLAIMS = {
    "main": ("ad_impressions_count ad_revenue_network ad_revenue_placement "
             "ad_revenue_unit adgroup android_id android_uuid api_level "
             "app_secret app_token app_version app_version_short att_status "
             "bundle_id callback_params campaign click_time "
             "click_time_server country created_at creative currency "
             "deduplication_id default_tracker details device_known "
             "device_name device_type environment event_callback_id "
             "event_count event_token external_device_id fb_anon_id fb_id "
             "ff_app_set_id_disabled ff_att_disabled ff_idfv_disabled "
             "ff_odm_enabled fire_adid fire_tracking_enabled "
             "found_location google_play_instant gps_adid gps_adid_src "
             "granular_third_party_sharing_options hardware_name idfa idfv "
             "initiated_by initiating_package_name install_begin_time "
             "install_begin_time_server install_version installed_at "
             "last_skan_update mcc measurement mnc needs_cost odm_info "
             "order_id originating_package_name os_build os_name "
             "os_version package_name params partner_params "
             "partner_sharing_settings payload primary_dedupe_token "
             "purchase_time push_token referrer referrer_api reftag "
             "revenue sales_region secondary_dedupe_token secret_id seq"
             ).split(),
    "tail": ("session_count session_length sharing skadn_registered_at "
             "source started_at store_app_id_from_client "
             "store_name_from_client store_name_from_system "
             "subsession_count time_spent tracker tracking_enabled "
             "updated_at").split(),
    "last": ("activity_kind client_sdk").split(),
}

def claims_string(val, c):
    """The exact claims bytes the block hash ingests."""
    out = ""
    for grp in ("main", "tail", "last"):
        out += "".join(str(val[k]) for k in CLAIMS[grp]
                       if val.get(k) not in (None, ""))
        if grp == "main":
            out += c["adj_signing_id"]
    return (out + c["headers_id"] + c["native_version"]).encode("latin1")

# -- the header: bionic rand() of the signing second ---------------------------
_M, _A = 2147483647, 16807               # MINSTD: Mersenne prime, 7**5
_Q, _R = _M // _A, _M % _A               # the Schrage split: 127773, 2836

def _schrage(prev):
    """One Lehmer step; division truncates toward zero, not floor."""
    if prev >= 0:
        hi, lo = divmod(prev, _Q)
    else:
        hi = -((-prev) // _Q)
        lo = prev - hi * _Q
    y = lo * _A - hi * _R
    return y + _M if y < 0 else y

def make_header(unix_sec):
    """MINSTD in Schrage's form, 31 state words, taps r[3]+r[0]."""
    s = unix_sec & 4294967295 or 1
    st = [s if s < _M else s - 4294967296] + [0] * 30
    for i in range(1, 31):
        st[i] = _schrage(st[i - 1])
    d = []
    for k in range(318):
        f, b = (3 + k) % 31, k % 31
        v = (st[f] + st[b]) & 4294967295
        st[f] = v if v < _M else v - 4294967296
        if k >= 310:
            d.append(v >> 1)
    return b"".join(struct.pack(">I", d[2 * i] ^ d[2 * i + 1])
                    for i in range(4))

# -- the head: 24 Lehmer draws (seed = u32be(nonce4)) drive a 16-slot
# -- Fisher-Yates shuffle; one bit forced on per halfword; 16x16 bit
# -- transpose; the eight masks (131 step 2) fold halfwords 8..15 by XOR.
HEAD_MASKS = tuple(131 + 2 * i for i in range(8))

def head_for(nonce4):
    state = struct.unpack(">I", bytes(nonce4))[0] or 123459876
    draws = []
    for _ in range(24):
        state = state * _A % _M
        draws.append(state)
    perm = list(range(16))
    for i in range(16):
        j = draws[i] % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    pre = []
    for i in range(16):
        v = (draws[16 + i // 2] >> 16 if i % 2 == 0
             else draws[16 + (i - 1) // 2])
        pos = 15 - perm[i]
        pre.append((v & ((1 << pos) - 1)) | (1 << pos))
    src = [sum(((pre[i] >> (15 - j)) & 1) << (15 - i) for i in range(16))
           for j in range(16)][8:]
    out = b""
    for msk in HEAD_MASKS:
        v = 0
        for k in range(8):
            if msk >> k & 1:
                v ^= src[7 - k]
        out += struct.pack(">H", v)
    return out

# -- SHA-256: the standard compression (hashlib cannot start from a custom IV,
# -- which the block law needs)

def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 4294967295

def _sha256_block(st, blk):
    w = list(blk)
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
        s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 4294967295)
    a, b, c, d, e, f, g, h = st
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        t1 = (h + S1 + (g ^ (e & (f ^ g))) + _K256[i] + w[i]) & 4294967295
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        t2 = S0 + ((a & b) ^ (a & c) ^ (b & c))
        h, g, f, e = g, f, e, (d + t1) & 4294967295
        d, c, b, a = c, b, a, (t1 + t2) & 4294967295
    return [(x + y) & 4294967295
            for x, y in zip(st, (a, b, c, d, e, f, g, h))]

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

# -- the block: SHA-256 chained from IV2, not the standard IV.  The lib's
# -- eight constant-push sites store IV2 XOR 3435973836 per dword; the
# -- state-loading helper unmasks each with 3435973836.
IV2 = tuple(w ^ 3435973836 for w in struct.unpack(
    ">8I", bytes.fromhex("018a6c12190ae32cce07f5493186d96fcb061855af48c1739da54cdc06cf339e")))

def record_block(head, nonce4, claims, cert):
    """The device stores the nonce raw and hashes it reversed."""
    msg = (cert + bytes((0, 8)) + head + bytes(nonce4)[::-1] + SHA0 +
           bytes((1,)) + claims)
    st = list(IV2)
    m = (msg + bytes((128,)) + bytes((0,)) * ((55 - len(msg)) % 64)
         + struct.pack(">Q", len(msg) * 8))
    for i in range(0, len(m), 64):
        st = _sha256_block(st, struct.unpack(">16I", m[i:i + 64]))
    return struct.pack(">8I", *st)

# -- the cipher: plain AES-256, CBC from the header as IV ----------------------

def _xtime(a):
    """GF(2^8) multiply by 2, mod x^8+x^4+x^3+x+1 (283)."""
    return ((a << 1) ^ 27) & 255 if a & 128 else (a << 1) & 255

def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p

def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 255

def _affine(y):
    return y ^ _rotl8(y, 1) ^ _rotl8(y, 2) ^ _rotl8(y, 3) ^ _rotl8(y, 4) ^ 99

SBOX = [_affine(0)] + [
    _affine(next(q for q in range(1, 256) if _gmul(v, q) == 1))
    for v in range(1, 256)]                      # affine(x^-1) ^ 99

def _key_schedule(key):
    """The standard AES-256 expansion: 15 round keys."""
    W = [list(key[i * 4:i * 4 + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(W[i - 1])
        if i % 8 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        W.append([W[i - 8][j] ^ t[j] for j in range(4)])
    return [[b for w in W[4 * r:4 * r + 4] for b in w] for r in range(15)]

_RK = _key_schedule(AES_KEY)

def _mix_col(col):
    return [(_gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]),
            (col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]),
            (col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)),
            (_gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2))]

def _encrypt_chunk(chunk):
    """AES-256 encrypt one 16-byte block with the fixed key."""
    x = [chunk[i] ^ _RK[0][i] for i in range(16)]
    for rnd in range(1, 14):
        x = [SBOX[b] for b in x]
        x = [col for c in range(4)
             for col in _mix_col([x[((c + r) % 4) * 4 + r] for r in range(4)])]
        x = [x[i] ^ _RK[rnd][i] for i in range(16)]
    x = [SBOX[b] for b in x]
    x = [x[((c + r) % 4) * 4 + r] for c in range(4) for r in range(4)]
    return bytes(x[i] ^ _RK[14][i] for i in range(16))

def encrypt(record, header):
    """128 B plaintext + 16 B IV -> the encrypted body (CBC)."""
    out, wa = b"", header
    for k in range(len(record) // 16):
        c = _encrypt_chunk([a ^ b for a, b in
                            zip(bytearray(record[16 * k:16 * k + 16]),
                                bytearray(wa))])
        out += c
        wa = c
    return out

# -- the signature ---------------------------------------------------------------

def sign(second, nonce4, claims, cert):
    """The 176-byte signature: header || encrypted record || tag."""
    if len(cert) != 20:
        raise ValueError("cert must be the 20-byte cert SHA-1 "
                         "(campaign cert_sha1; graddef's is still empty)")
    head = head_for(nonce4)
    record = b"".join((bytes((1, 0, 8)), head, bytes((2,)), bytes(nonce4),
                       bytes((3,)), cert, bytes((4,)),
                       record_block(head, nonce4, claims, cert), bytes((5,)),
                       SHA0, bytes((6, 1, 15)), bytes([15]) * 14))
    header = make_header(int(second))
    body = encrypt(record, header)
    return header + body + hmac.new(DK38, body, hashlib.sha256).digest()

def sign_request(fields, kind, c, second=None, nonce4=None):
    """Sign one request and return the Authorization header VALUE.

    c = the campaign's signer fields (campaign_data.signer_fields()):
    cert_sha1 (required), client_sdk, adj_signing_id, headers_id,
    native_version, algorithm.
    """
    val = dict(fields)
    val["activity_kind"] = "click" if kind == "sdk_click" else kind
    val["client_sdk"] = c["client_sdk"]
    second = int(second if second is not None else time.time())
    nonce4 = os.urandom(4) if nonce4 is None else bytes(bytearray(nonce4))
    blob = sign(second, nonce4, claims_string(val, c),
                bytes(bytearray.fromhex(c["cert_sha1"])))
    return ('Signature signature="%s",adj_signing_id="%s",algorithm="%s",'
            'headers_id="%s",native_version="%s"'
            % (base64.b64encode(blob).decode("ascii"), c["adj_signing_id"],
               c["algorithm"], c["headers_id"], c["native_version"]))
