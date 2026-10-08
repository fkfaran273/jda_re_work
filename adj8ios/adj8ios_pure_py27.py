# -*- coding: utf-8 -*-
"""adj8ios_pure_py27.py -- the adj8-iOS signature, Python 2.7.

Generated from adj8ios_pure.py by make_py27_adj8ios.py.  Same algorithm,
same bytes; only the syntax is 2.7.  Do not edit by hand -- change
adj8ios_pure.py and re-run the generator.

adj8ios_pure.py -- the Adjust adj8 signature on iOS, in pure Python.

Derived from the adj8-Android law (adj8/adj8_pure.py) plus the two iOS-only
pieces recovered from the adj9-iOS work, and verified byte-exact against 7
genuine device blobs (neomindios_adjust.saz, wave_19may_install_newapp_ios8.chls,
niceoneiosauto_6may_lvl2_ios11.chls).

    blob(176) = header(16) || body(128) || tag(32)

  header  iOS MINSTD:  x = (second mod 2^31-1), 0 -> 1;  8 draws x = 16807*x mod p;
          w_i = d[2i] ^ d[2i+1], big-endian.            <- iOS generator (adj8-Android
          uses the 31-word bionic rand instead; same MINSTD seed, different taps)
  record  01 00 08 | head16[3:19] | 02 | S BE32[20:24] | 03 | d9 = 00*20[25:45]
          | 04 | block32[46:78] | 05 | sha256("")[79:111] | 06 | 02 | 0f*15[113:128]
  head16  the d0 selector head for seed S, selector phase (0x09,) -- the same
          construction as adj9-iOS, identical code path
  block   sha256_iv2( d9 || 00 08 || head16 || rev4(S) || sha256("") || 0x02 || claims )
  claims  pool-order values (97-key pool, split at session_count, adj_signing_id
          pinned at the split) || activity_kind || client_sdk || headers_id
          || native_version   -- values only, concatenated bare
  body    AES-256-CBC over the record, key = the lib constant, IV = header
  tag     HMAC-SHA256(DK38, body)                       <- same key as adj8-Android

  auth    Signature signature="<BASE64>",adj_signing_id="1400000",algorithm="adj8",
          headers_id="9",native_version="3.67.0"

  client_sdk is the FULL client-sdk header value, e.g. "web-bridge5.6.2@ios5.6.2"
  (bridge apps), "react-native5.6.0@ios5.6.2" (RN apps) or plain "ios5.6.2".

  USE   auth = sign_request(fields, kind, c, second=sec, nonce4=b'....')
"""
import base64
import binascii
import hashlib, hmac, json, os, struct, sys, time

def _b(x):
    """bytes() shim: return a bytearray so iteration yields ints on py2."""
    if isinstance(x, int):
        return bytearray(x)
    if isinstance(x, unicode):
        return bytearray(x.encode("latin-1"))
    return bytearray(x)


def _hex(x):
    """bytes.hex() shim."""
    return binascii.hexlify(bytearray(x)).decode("ascii")


SHA0 = hashlib.sha256(b"").digest()

# -- the two recorded lib immediates (identical to the adj8-Android native) ----
DK38 = bytearray.fromhex("caab83444a2146392abb96b64230615529a770c63c163c1c7528673e0671728f")
AES_KEY = bytearray.fromhex("ffb5e5f9c862b637d13351c292633e39965a3c2d037ed64dfff5388e11d80db3")

# -- the claims law: the native's pool in emission order, present keys only,
# -- values concatenated bare, adj_signing_id pinned at the session_count split,
# -- headers_id + native_version close the string.  The pool is the Android
# -- libsigner table (95 sorted core keys + secret_id, activity_kind, client_sdk),
# -- a cross-platform UNION: bundle_id / idfa / idfv / att_status / app_version_short
# -- are iOS-only and simply fire here.
POOL_MAIN = (
    "ad_impressions_count ad_revenue_network ad_revenue_placement ad_revenue_unit "
    "adgroup android_id android_uuid api_level app_secret app_token app_version "
    "app_version_short att_status bundle_id callback_params campaign click_time "
    "click_time_server country created_at creative currency deduplication_id "
    "default_tracker details device_known device_name device_type environment "
    "event_callback_id event_count event_token external_device_id fb_anon_id fb_id "
    "ff_app_set_id_disabled ff_att_disabled ff_idfv_disabled ff_odm_enabled fire_adid "
    "fire_tracking_enabled found_location google_play_instant gps_adid gps_adid_src "
    "granular_third_party_sharing_options hardware_name idfa idfv initiated_by "
    "initiating_package_name install_begin_time install_begin_time_server "
    "install_version installed_at last_skan_update mcc measurement mnc needs_cost "
    "odm_info order_id originating_package_name os_build os_name os_version "
    "package_name params partner_params partner_sharing_settings payload "
    "primary_dedupe_token purchase_time push_token referrer referrer_api reftag "
    "revenue sales_region secondary_dedupe_token secret_id seq").split()
POOL_REST = (
    "session_count session_length sharing skadn_registered_at source started_at "
    "store_app_id_from_client store_name_from_client store_name_from_system "
    "subsession_count time_spent tracker tracking_enabled updated_at "
    "activity_kind client_sdk").split()
SPLIT = POOL_MAIN.index("seq") + 1          # everything up to here, then the pin


def claims_string(val, c):
    """The exact claims bytes the block hash ingests."""
    parts = [str(val[k]) for k in POOL_MAIN if val.get(k) not in (None, "")]
    parts.append(c["adjust"]["adj_signing_id"])
    parts += [str(val[k]) for k in POOL_REST if val.get(k) not in (None, "")]
    return ("".join(parts) + c["adjust"]["headers_id"]
            + c["adjust"]["native_version"]).encode("latin-1")


# -- PART 1: the iOS header (MINSTD, pair-XOR, big-endian) ---------------------

_MINSTD_M = (1 << 31) - 1
_MINSTD_A = 7 ** 5                        # 16807
_MINSTD_Q = _MINSTD_M // _MINSTD_A
_MINSTD_R = _MINSTD_M % _MINSTD_A
_MASK16 = (1 << 16) - 1
_MASK32 = (1 << 32) - 1


def minstd_state(unix_sec):
    x = int(unix_sec) % _MINSTD_M
    return 1 if x == 0 else x


def minstd_draws(unix_sec, n=8):
    x = minstd_state(unix_sec)
    out = []
    for _ in range(n):
        x = (_MINSTD_A * x) % _MINSTD_M
        out.append(x)
    return out


def make_header(unix_sec):
    """The 16-byte header an iOS device mints for a signing second."""
    d = minstd_draws(unix_sec, 8)
    words = [(d[2 * i] ^ d[2 * i + 1]) & _MASK32 for i in range(4)]
    return b"".join(struct.pack(">I", w) for w in words)


# -- PART 2: seed S -> the d0 head (selector phase (0x09,) on iOS) ------------

ZERO_STATE_SEED = 1


def _step(x):
    """One MINSTD Schrage step of the region PRNG."""
    if x == 0:
        x = ZERO_STATE_SEED
    hi, lo = divmod(x, _MINSTD_Q)
    y = lo * _MINSTD_A - hi * _MINSTD_R
    if y < 0:
        y += _MINSTD_M
    return y & _MINSTD_M


def _raw16(seed):
    """16 halfwords: Fisher-Yates shuffle + paired consumption."""
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
    raw = _transpose16(_raw16(seed))
    packed = b"".join(struct.pack("<H", x) for x in raw)
    return [struct.unpack(">I", packed[i:i + 4])[0] for i in range(0, 32, 4)]


def _d0_source(d4):
    d4_bytes = b"".join(struct.pack(">I", w) for w in d4)
    return [struct.unpack("<H", d4_bytes[i:i + 2])[0] for i in range(16, 32, 2)]


def _selector_halfword(mask, source):
    value = 0
    for bit in range(8):
        if (mask >> bit) & 1:
            value ^= source[7 - bit]
    return value & _MASK16


def _d0_words(d4, head=None):
    source = _d0_source(d4)
    prefix = IOS_HEAD_PHASE if head is None else tuple(head)
    selectors = tuple(prefix[i] if i < len(prefix) else (0x40 | (i & 7))
                      for i in range(72))
    values = [_selector_halfword((s << 1) + 3, source) for s in selectors]
    raw = b"".join(struct.pack("<H", v) for v in values)
    return [struct.unpack(">I", raw[i:i + 4])[0] for i in range(0, 144, 4)]


def head_words(d0w):
    return b"".join(struct.pack("<I", ((w & 0xFFFF) << 16) | (w >> 16))
                    for w in d0w[:4])


def head16_for(S, head=None):
    """The 16-byte d0 head the record carries for seed S."""
    return head_words(_d0_words(_d4_words(int(S) & _MASK32), head=head))


IOS_HEAD_PHASE = (0x09,)        # the selector phase every capture carries
ADJ_SIGNING_ID = "1400000"
ALGORITHM = "adj8"
HEADERS_ID = "9"
NATIVE_VERSION = "3.67.0"
VARIANT = 0x02                  # iOS; the Android native writes 0x01 here
D9 = b"\x00" * 20               # iOS: the cert slot is all zero


# -- PART 3: SHA-256 chained from the custom IV2 (the block hash) ------------

def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _primes(n):
    out, i = [], 2
    while len(out) < n:
        if all(i % p for p in out if p * p <= i):
            out.append(i)
        i += 1
    return out


def _frac_cbrt(p):
    """floor(frac(cbrt(p)) * 2**32), exact integer arithmetic."""
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


_K256 = tuple(_frac_cbrt(p) for p in _primes(64))


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
    return [(x + y) & _MASK32
            for x, y in zip(st, (a, b, c, d, e, f, g, h))]


# the lib stores IV2 XOR 3435973836 per dword and unmasks on load
IV2 = tuple(w ^ 3435973836 for w in struct.unpack(
    ">8I", bytearray.fromhex("018a6c12190ae32cce07f5493186d96fcb061855af48c1739da54cdc06cf339e")))


def sha256_iv2(msg):
    st = list(IV2)
    m = (msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64)
         + struct.pack(">Q", len(msg) * 8))
    for i in range(0, len(m), 64):
        st = _sha256_block(st, struct.unpack(">16I", m[i:i + 64]))
    return struct.pack(">8I", *st)


# -- PART 4: the cipher (plain AES-256, CBC from the header as IV) ------------

def _xtime(a):
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
    for v in range(1, 256)]


def _key_schedule(key):
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
    return [_gmul(m[0], col[0]) ^ _gmul(m[1], col[1]) ^ _gmul(m[2], col[2])
            ^ _gmul(m[3], col[3])
            for m in ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))]


def _encrypt_chunk(chunk):
    x = [chunk[i] ^ _RK[0][i] for i in range(16)]
    for rnd in range(1, 14):
        x = [SBOX[b] for b in x]
        x = [c for c in range(4)
             for c in _mix_col([x[((c + r) % 4) * 4 + r] for r in range(4)])]
        x = [x[i] ^ _RK[rnd][i] for i in range(16)]
    x = [SBOX[b] for b in x]
    x = [x[((c + r) % 4) * 4 + r] for c in range(4) for r in range(4)]
    return _b(x[i] ^ _RK[14][i] for i in range(16))


def encrypt(record, header):
    """128 B plaintext + 16 B IV -> the encrypted body (CBC)."""
    out, wa = b"", header
    for k in range(0, len(record), 16):
        c = _encrypt_chunk([a ^ b for a, b in
                            zip(bytearray(record[k:k + 16]),
                                bytearray(wa))])
        out += c
        wa = c
    return out


# -- PART 5: the record + the mint -------------------------------------------

def build_record(S, head16, claims, d9=D9, variant=VARIANT):
    """The 128-byte iOS record.  Android = the same with a real cert + 0x01."""
    head16 = _b(head16)
    d9 = _b(d9)
    if len(head16) != 16:
        raise ValueError("head16 must be 16 bytes")
    if len(d9) != 20:
        raise ValueError("d9 must be 20 bytes")
    block = sha256_iv2(d9 + b"\x00\x08" + head16
                       + struct.pack("<I", S & _MASK32)   # record stores BE32, msg LE32
                       + SHA0 + _b([variant]) + claims)
    out = bytearray(128)
    out[0:3] = b"\x01\x00\x08"
    out[3:19] = head16
    out[19] = 0x02
    out[20:24] = struct.pack(">I", S & _MASK32)
    out[24] = 0x03
    out[25:45] = d9
    out[45] = 0x04
    out[46:78] = block
    out[78] = 0x05
    out[79:111] = SHA0
    out[111] = 0x06
    out[112] = variant
    out[113:128] = b"\x0f" * 15
    return _b(out)


def sign(second, nonce4, claims, d9=D9, variant=VARIANT, head=None):
    """The 176-byte signature: header || encrypted record || tag."""
    S = struct.unpack(">I", _b(nonce4))[0]
    head16 = head16_for(S, head)
    record = build_record(S, head16, claims, d9=d9, variant=variant)
    header = make_header(int(second))
    body = encrypt(record, header)
    return header + body + hmac.new(DK38, body, hashlib.sha256).digest()


KINDS = ("session", "click", "event", "attribution", "info")
# activity_kind per request kind: sdk_click signs as "click"; the /sdk_info
# endpoint signs as "info" (verified on the niceone capture).
_ACTIVITY = {"click": "click", "sdk_click": "click", "info": "info"}


def sign_request(fields, kind, c, second=None, nonce4=None):
    """Sign one request and return the Authorization header VALUE.

    fields : the request's decoded wire params (str -> str)
    kind   : session | click | event | attribution | sdk_info
    c      : the campaign dict, backend shape: c["adjust"] = {sdk,
             adj_signing_id, headers_id, algorithm, native_version}
    second : signing second (default now) -- seeds the MINSTD header
    nonce4 : the 4-byte seed S (default random, generated inside)
    """
    if kind not in KINDS:
        raise ValueError("kind must be one of %r" % (KINDS,))
    adj = c["adjust"]
    val = dict(fields)
    val["activity_kind"] = _ACTIVITY.get(kind, kind)
    val["client_sdk"] = adj["sdk"]
    second = int(second if second is not None else time.time())
    nonce4 = os.urandom(4) if nonce4 is None else _b(bytearray(nonce4))
    blob = sign(second, nonce4, claims_string(val, c),
                head=tuple(c.get("head_phase", IOS_HEAD_PHASE)))
    return ('Signature signature="%s",adj_signing_id="%s",algorithm="%s",'
            'headers_id="%s",native_version="%s"'
            % (base64.b64encode(blob).decode("ascii"), adj["adj_signing_id"],
               adj.get("algorithm", ALGORITHM), adj["headers_id"],
               adj["native_version"]))


# -- PART 6: the frozen genuine capture blobs (the byte-exact proof) ---------

def _gold():
    import os.path
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "gold_vectors.json")
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        return json.load(fh)


def self_test(verbose=True):
    ok = tot = 0
    for v in _gold():
        c = {"adjust": {"sdk": v["client_sdk"],
                        "adj_signing_id": ADJ_SIGNING_ID,
                        "headers_id": HEADERS_ID,
                        "algorithm": ALGORITHM,
                        "native_version": NATIVE_VERSION}}
        auth = sign_request(v["params"], v["kind"], c,
                            second=v["second"], nonce4=bytearray.fromhex(v["nonce4"]))
        want = base64.b64encode(bytearray.fromhex(v["blob_hex"])).decode()
        good = ('signature="%s"' % want) in auth
        tot += 1
        ok += good
        if verbose:
            print("[PURE] %-4s %-13s second=%d %s"
                  % (v["n"], v["kind"], v["second"],
                     "BYTE-EXACT" if good else "MISMATCH"))
    if verbose:
        print("[PURE] self_test: %d/%d byte-exact vs genuine device blobs" % (ok, tot))
    return ok == tot and tot > 0


if __name__ == "__main__":
    sys.exit(0 if self_test() else 1)
