"""adj8_pure.py -- the Adjust adj8 signature in pure Python.  No VM.

    blob = header(16) || AES-256-CBC record(128) || tag(32)

  header  bionic rand() seeded by the signing second: 310 warm-up draws,
          then eight draws XORed in pairs, big-endian.
  record  head from the 4-byte nonce; nonce4 (raw), the cert SHA-1 and the
          block -- SHA-256 chained from IV2 over cert || 00 08 || head ||
          rev4(nonce4) || sha256("") || 01 || claims.  CBC with the fixed
          key, IV = header; tag = HMAC-SHA256(DK38) over the body.

  RECORDED  DK38, AES_KEY: lib immediates, no generating rule.  Derived: the
  head masks (131 step 2), IV2 (lib immediates XOR 3435973836), the S-box,
  the AES-256 schedule, the SHA-256 constants (cube roots of primes).
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
# -- close the string.  The pool IS the Android lib's table (recovered from
# -- the obfuscated strings of libsigner 3.62.0, adj7_work/adj7s4_pool_order;
# -- 3.67.0 adds secret_id): it is a cross-platform UNION, so iOS-only names
# -- (bundle_id, idfa, idfv, att_status, skadn_*, app_version_short) sit in
# -- it and never fire on Android -- the SDK never puts them in the map.
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
    "rest": ("session_count session_length sharing skadn_registered_at "
             "source started_at store_app_id_from_client "
             "store_name_from_client store_name_from_system "
             "subsession_count time_spent tracker tracking_enabled "
             "updated_at activity_kind client_sdk").split(),
}

def claims_string(val, c):
    """The exact claims bytes the block hash ingests."""
    parts = [str(val[k]) for k in CLAIMS["main"]
             if val.get(k) not in (None, "")]
    parts.append(c["adjust"]["adj_signing_id"])
    parts += [str(val[k]) for k in CLAIMS["rest"]
              if val.get(k) not in (None, "")]
    return ("".join(parts) + c["adjust"]["headers_id"] +
            c["adjust"]["native_version"]).encode("latin1")

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
# -- transpose; the eight fold masks (131 step 2) fold halfwords 8..15.

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
        v = draws[16 + i // 2] >> (16 if i % 2 == 0 else 0)
        pos = 15 - perm[i]
        pre.append((v & ((1 << pos) - 1)) | (1 << pos))
    src = [sum(((pre[i] >> (15 - j)) & 1) << (15 - i) for i in range(16))
           for j in range(16)][8:]
    out = b""
    for msk in range(131, 147, 2):
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
    """AES MixColumns."""
    return [_gmul(m[0], col[0]) ^ _gmul(m[1], col[1]) ^ _gmul(m[2], col[2])
            ^ _gmul(m[3], col[3])
            for m in ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))]

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
    for k in range(0, len(record), 16):
        c = _encrypt_chunk([a ^ b for a, b in
                            zip(bytearray(record[k:k + 16]), bytearray(wa))])
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

    c = the campaign dict, the backend's format: adjust{sdk, adj_signing_id,
    headers_id, native_version, algorithm} + cert_sha1.
    """
    val = dict(fields)
    val["activity_kind"] = "click" if kind == "sdk_click" else kind
    val["client_sdk"] = c["adjust"]["sdk"]
    second = int(second if second is not None else time.time())
    nonce4 = os.urandom(4) if nonce4 is None else bytes(bytearray(nonce4))
    blob = sign(second, nonce4, claims_string(val, c),
                bytes(bytearray.fromhex(c["cert_sha1"])))
    return ('Signature signature="%s",adj_signing_id="%s",algorithm="%s",'
            'headers_id="%s",native_version="%s"'
            % (base64.b64encode(blob).decode("ascii"),
               c["adjust"]["adj_signing_id"], c["adjust"]["algorithm"],
               c["adjust"]["headers_id"], c["adjust"]["native_version"]))


# -- the replay-rule API (the shape replay_attr_test.py / run_graddef.py use).
# -- DEVICE_PROPS is the device story the native fingerprints; on the pure
# -- signer it is carried for interface compatibility: the claims law ingests
# -- the wire MAP (which already carries os_version/api_level/device_name/...),
# -- never the raw props, so props cannot change a signature.
DEVICE_PROPS = {
    b"ro.product.name": b"hawao_g",
    b"ro.product.model": b"moto g42",
    b"ro.product.manufacturer": b"motorola",
    b"ro.product.device": b"hawao",
    b"ro.product.cpu.abilist": b"arm64-v8a,armeabi-v7a,armeabi",
    b"ro.product.brand": b"motorola",
    b"ro.hardware": b"qcom",
    b"ro.build.version.sdk": b"31",
    b"ro.build.version.release": b"12",
    b"ro.build.user": b"hudsoncm",
    b"ro.build.type": b"user",
    b"ro.build.host": b"ilclbld161",
    b"ro.build.fingerprint": (b"motorola/hawao_g/hawao:12/S2SE32.28-28-4/"
                              b"4140d-bd21d:user/release-keys"),
    b"ro.build.display.id": b"S2SE32.28-28-4",
    b"ro.bootloader": b"MBM-3.0-hawao_g-182ec3123a-220525",
}

_APKS = None

def _campaign_for(fields):
    """The campaign dict for this wire map, by package_name."""
    global _APKS
    if _APKS is None:
        import campaign_data
        _APKS = {v["package_name"]: v
                 for v in campaign_data.CAMPAIGNS.values()}
    return _APKS[fields["package_name"]]

def _cert_sha1_from_apk(apk):
    """SHA-1 of the first X.509 cert in the APK's v2 Signing Block (the
    v2-signed APKs have no META-INF/*.RSA; the native reads the cert from
    the APK the same way)."""
    i = apk.rfind(b"APK Sig Block 42")
    if i < 8:
        raise ValueError("no v2 signing block in apk_bytes")
    # layout: [u64 size][pairs...][u64 size]["APK Sig Block 42" at i]
    (size2,) = struct.unpack("<Q", apk[i - 8:i])
    start = i + 16 - int(size2)
    if start < 0 or start >= i - 8:
        raise ValueError("bad v2 block size prefix")
    pos = start
    while pos + 8 <= i - 8:
        (plen,) = struct.unpack("<Q", apk[pos:pos + 8])
        plen = int(plen)
        pair = apk[pos + 8:pos + 8 + plen]
        if len(pair) < 8:
            break
        (pid,) = struct.unpack("<I", pair[0:4])
        if pid == 0x7109871a:                      # APK Signature Scheme v2
            val = pair[4:]
            # value = u32 signers_len | signers
            (slen,) = struct.unpack("<I", val[0:4])
            s = val[4:4 + int(slen)]
            # signer = u32 signer_len | content;
            # content = u32 signed_data_len | signed_data | ...
            (k,) = struct.unpack("<I", s[0:4])
            sc = s[4:4 + int(k)]
            (sdl,) = struct.unpack("<I", sc[0:4])
            sd = sc[4:4 + int(sdl)]
            # signed_data = u32 digests | digests | u32 certs | certs | ...
            (dlen,) = struct.unpack("<I", sd[0:4])
            rest = sd[4 + int(dlen):]
            (clen,) = struct.unpack("<I", rest[0:4])
            certs = rest[4:4 + int(clen)]
            # certs = u32 cert_len | cert DER | ...
            (xlen,) = struct.unpack("<I", certs[0:4])
            der = certs[4:4 + int(xlen)]
            if len(der) != int(xlen) or der[:1] != b"\x30":
                raise ValueError("bad v2 certificate payload")
            return hashlib.sha1(der).hexdigest()
        pos += 8 + plen
    raise ValueError("v2 block found but no signer payload")

def mint_adj8(kind, fields, unix_sec=None, apk_path=None, apk_bytes=None,
              return_meta=False, urandom_bytes=None, device_props=None):
    """Mint one adj8 signature for the replay rule scripts.

    kind      : session | click | event | attribution (interface compat; the
                activity_kind follows the wire law inside sign_request)
    fields    : the wire map (str -> str)
    unix_sec  : the signing second (drives the header PRNG)
    apk_bytes : when the campaign has no recorded cert_sha1 (v2-signed
                APKs), the cert SHA-1 is extracted from these bytes

    returns (blob176, auth_header) [, meta when return_meta=True].
    """
    if device_props:
        DEVICE_PROPS.clear()
        DEVICE_PROPS.update(device_props)
    c = _campaign_for(fields)
    cert = c.get("cert_sha1") or ""
    if not cert and apk_bytes:
        cert = _cert_sha1_from_apk(apk_bytes)
    if not cert:
        raise ValueError("no cert_sha1 for %s and no apk_bytes"
                         % fields.get("package_name"))
    cc = dict(c)
    cc["cert_sha1"] = cert
    auth = sign_request(fields, "sdk_click" if kind == "click" else kind,
                        cc, second=unix_sec)
    sig = auth.split('signature="', 1)[1].split('"', 1)[0]
    blob = base64.b64decode(sig)
    if return_meta:
        body = blob[16:-32]
        meta = {"second": int(unix_sec), "kind": kind,
                "tag_ok": hmac.new(DK38, body,
                                   hashlib.sha256).digest() == blob[-32:],
                "header_ok": blob[:16] == make_header(int(unix_sec)),
                "cert_sha1": cert}
        return blob, auth, meta
    return blob, auth


# -- the REAL-DEVICE claims law (work/cap/dev_law.py, proven byte-exact on
# -- the 3 genuine moto g42 blobs 2026-10-04 and re-verified 2026-10-08):
# -- pool claims WITHOUT the trailing headers_id/native_version, then the
# -- endpoint's activity_kind, then client_sdk, then headers_id + native.
DEVICE_CLIENT_SDK = "android5.7.0"

def build_claims(params):
    """Pool serialization only — no trailing header bytes (dev law base)."""
    pool = CLAIMS["main"] + CLAIMS["rest"]
    split = pool.index("session_count")
    profile, tail = pool[:split], pool[split:]
    parts = [str(params[k]) for k in profile
             if params.get(k) not in (None, "")]
    parts.append("1400000")
    parts += [str(params[k]) for k in tail
              if params.get(k) not in (None, "")]
    return "".join(parts).encode("latin1")

def device_claims(params, kind):
    """The full device claims string the block hash ingests."""
    return (build_claims(params) + str(kind).encode("latin1") +
            DEVICE_CLIENT_SDK.encode("latin1") +
            b"9" + b"3.67.0")

def device_sign(kind, params, unix_sec, nonce4, cert):
    """The REAL-DEVICE blob: head seeded by u32be(nonce4) (raw stored),
    block over cert + 00 08 + head + rev4(nonce4) + SHA0 + 01 + claims.
    nonce4 = the RAW 4 bytes stored at record[20:24]."""
    if len(cert) != 20:
        raise ValueError("cert must be 20 bytes")
    kind = {"sdk_click": "click"}.get(kind, kind)
    nonce4 = bytes(nonce4)
    head = head_for(nonce4)
    claims = device_claims(params, kind)
    msg = (bytes(cert) + bytes((0, 8)) + head + nonce4[::-1] + SHA0 +
           bytes((1,)) + claims)
    st = list(IV2)
    m = (msg + bytes((128,)) + bytes((0,)) * ((55 - len(msg)) % 64)
         + struct.pack(">Q", len(msg) * 8))
    for i in range(0, len(m), 64):
        st = _sha256_block(st, struct.unpack(">16I", m[i:i + 64]))
    block = struct.pack(">8I", *st)
    record = b"".join((bytes((1, 0, 8)), head, bytes((2,)), nonce4,
                       bytes((3,)), cert, bytes((4,)), block, bytes((5,)),
                       SHA0, bytes((6, 1, 15)), bytes([15]) * 14))
    header = make_header(int(unix_sec))
    body = encrypt(record, header)
    blob = header + body + hmac.new(DK38, body, hashlib.sha256).digest()
    auth = ('Signature signature="%s",adj_signing_id="1400000",'
            'algorithm="adj8",headers_id="9",native_version="3.67.0"'
            % base64.b64encode(blob).decode("ascii"))
    return blob, auth
