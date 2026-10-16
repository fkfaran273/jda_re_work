# -*- coding: utf-8 -*-
"""adj7ios_pure.py -- the Adjust **adj7** signature on **iOS**, pure Python.

Standalone (no import from adj7/): the shared Android core plus the iOS
deltas, verified byte-exact on TWO independent captures:

  nirio   com.fdjservices.nirio     ios5.4.6  native 3.61.0  headers_id 7
  watsons com.alfuttaim.watsons.uae ios5.5.0  native 3.62.0  headers_id 8

THE LAW (Android adj7 law with ONE crypto delta):

    blob(304) = header(16) || body(256) || tag(32)

    header    raw MINSTD:  x = signing unix second mod 2^31-1 (0 -> 1);
              8 draws x = 16807*x mod p;  w_i = d[2i]^d[2i+1] big-endian.
              (Android uses the bionic 31-word LCG + 310-draw warm-up.)
    body      CBC-AES-256 over the record, key = SEED, IV = header,
              the measured ShiftRows SPN with NO final SubBytes.
    record    '{ "a":  <A> ,"b": "<H>","c": "<cert40>","d": "<D8>",
                "e": "<sha256('') hex-upper>" }\\x00' + 0x10 * 16
              A = str(u64le(nonce12[:8])) rjust 20; D8 = hex-upper of the
              last 4 nonce bytes.
    cert40    ASCII "0"*40  (iOS no-cert path; Android: NUL bytes)
    H         sha256 with the custom IV0 over cert40 || nonce12 ||
              SHA0_HEX || claims
    claims    the 98-key pool order, present values bare-concatenated,
              adj_signing_id "1300000" pinned before "seq", block2
              (activity_kind, client_sdk) appended last
    tag       HMAC-SHA256(DK37, body)

    auth      Signature signature="<608 hex UPPER>",adj_signing_id="1300000",
              algorithm="adj7",headers_id="<7|8 per SDK build>",
              native_version="<3.61.0|3.62.0 per SDK build>"

activity_kind per endpoint (all confirmed byte-exact on captures):

    /session -> session          /sdk_click -> click
    /attribution -> attribution  /sdk_info -> info      (NOT sdk_info)
    /third_party_sharing -> third_party_sharing

    python adj7ios_pure.py     # selftest vs gold_vectors.json (10 vectors)
"""
import binascii
import hashlib
import hmac
import json
import os
import re
import struct
import time

# ------------------------------------------------------------------ consts
SEED = binascii.unhexlify(
    "f110fb41676dba311f38c652c8f951ec"
    "3db456c07b9166a509bef66cd870654b")            # AES-256 key
DK37 = binascii.unhexlify(
    "2a4cc07960d647623cc386dcefafbf25"
    "b669914d32cc8585a1ed7f920ef591eb")            # tag MAC key
IV0 = (0x16ba6d02, 0x11a298c2, 0x82187e46, 0x4c148c22,
       0x3a5cbc15, 0x06519f14, 0x97b9e370, 0x08ec3bec)  # commitment IV
ADJ_SIGNING_ID = "1300000"
ALGORITHM = "adj7"

CLAIM_POOL = (
    "ad_impressions_count ad_revenue_network ad_revenue_placement "
    "ad_revenue_unit adgroup android_id android_uuid api_level "
    "app_secret app_token app_version app_version_short att_status "
    "bundle_id callback_params campaign click_time click_time_server "
    "country created_at creative currency deduplication_id "
    "default_tracker details device_known device_name device_type "
    "environment event_callback_id event_count event_token "
    "external_device_id fb_anon_id fb_id ff_app_set_id_disabled "
    "ff_att_disabled ff_idfv_disabled ff_odm_enabled fire_adid "
    "fire_tracking_enabled found_location google_play_instant gps_adid "
    "gps_adid_src granular_third_party_sharing_options hardware_name "
    "idfa idfv initiated_by initiating_package_name install_begin_time "
    "install_begin_time_server install_version installed_at "
    "last_skan_update mcc measurement mnc needs_cost odm_info order_id "
    "originating_package_name os_build os_name os_version package_name "
    "params partner_params partner_sharing_settings payload "
    "primary_dedupe_token purchase_time push_token referrer referrer_api "
    "reftag revenue sales_region secondary_dedupe_token secret_id seq "
    "session_count session_length sharing skadn_registered_at source "
    "started_at store_app_id_from_client store_name_from_client "
    "store_name_from_system subsession_count time_spent tracker "
    "tracking_enabled updated_at activity_kind client_sdk").split()

def _hexup(b):
    """binascii.hexlify works on both; .hex() does not exist on py2."""
    return binascii.hexlify(bytes(bytearray(b))).upper()


def _latin1(s):
    """str -> bytes in latin-1 on BOTH pythons."""
    return bytes(bytearray(s, "latin1"))


SHA0 = hashlib.sha256(b"").digest()
SHA0_HEX = binascii.hexlify(SHA0).upper()
CERT40_IOS = b"0" * 40

# ----------------------------------------------------------------- header
_M31, _A31 = 2147483647, 16807


def make_header(unix_sec):
    """raw MINSTD (Lehmer), 8 draws, pair-XOR, big-endian."""
    x = int(unix_sec) % _M31 or 1
    d = []
    for _ in range(8):
        x = (_A31 * x) % _M31
        d.append(x)
    w = [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return b"".join(struct.pack(">I", v) for v in w)


# ----------------------------------------------------------------- claims
def build_claims(kind, params, client_sdk="", include_block2=True):
    m = dict(params)
    if include_block2:
        m.setdefault("activity_kind", kind)
        m.setdefault("client_sdk", client_sdk)
    split = CLAIM_POOL.index("seq")
    profile, tail, block2 = CLAIM_POOL[:split], CLAIM_POOL[split:-2], CLAIM_POOL[-2:]
    parts = [str(m[k]) for k in profile if m.get(k) not in (None, "")]
    parts.append(ADJ_SIGNING_ID)
    parts += [str(m[k]) for k in tail if m.get(k) not in (None, "")]
    parts += [str(m[k]) for k in block2 if m.get(k) not in (None, "")]
    return _latin1("".join(parts))


# ------------------------------------------------- commitment sha256 (IV0)
def _primes(n):
    out, i = [], 2
    while len(out) < n:
        if all(i % p for p in out if p * p <= i):
            out.append(i)
        i += 1
    return out


def _frac_cbrt(p):
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
_M32 = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _M32


def _sha256_block(state, blk):
    w = list(blk)
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
        s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _M32)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        t1 = (h + s1 + ((e & f) ^ ((~e & _M32) & g)) + _K256[i] + w[i]) & _M32
        s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        t2 = (s0 + ((a & b) ^ (a & c) ^ (b & c))) & _M32
        h, g, f = g, f, e
        e = (d + t1) & _M32
        d, c, b = c, b, a
        a = (t1 + t2) & _M32
    return [(x + st) & _M32 for x, st in zip((a, b, c, d, e, f, g, h), state)]


def sha256_iv0(msg):
    padded = (msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64)
              + struct.pack(">Q", len(msg) * 8))
    state = list(IV0)
    for i in range(0, len(padded), 64):
        state = _sha256_block(state, struct.unpack(">16I", padded[i:i + 64]))
    return struct.pack(">8I", *state)


def commitment_digest(claims, nonce12):
    return sha256_iv0(CERT40_IOS + nonce12 + SHA0_HEX.encode() + claims)


def build_record(H, nonce12):
    A = str(struct.unpack("<Q", nonce12[0:8])[0]).rjust(20)
    d8 = _hexup(nonce12[8:12])
    j = (b'{ "a":  ' + A.encode() + b' ,"b": "' + _hexup(H).encode()
         + b'","c": "' + CERT40_IOS + b'","d": "' + d8.encode()
         + b'","e": "' + SHA0_HEX.encode() + b'" }\x00')
    return j + b"\x10" * (256 - len(j))


# ----------------------------------------------- AES-256 (measured SPN)
def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _affine(y):
    return (y ^ _rotl8(y, 1) ^ _rotl8(y, 2) ^ _rotl8(y, 3)
            ^ _rotl8(y, 4) ^ 0x63)


AES_SBOX = bytes(bytearray(
    _affine(next(q for q in range(1, 256) if _gmul(v, q) == 1))
    if v else _affine(0) for v in range(256)))
INVBOX = [0] * 256
for _i, _v in enumerate(bytearray(AES_SBOX)):
    INVBOX[_v] = _i


def _key_schedule(key):
    kb = bytearray(key)
    W = [list(kb[i * 4:i * 4 + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(W[i - 1])
        if i % 8 == 0:
            t = [bytearray(AES_SBOX)[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [bytearray(AES_SBOX)[b] for b in t]
        W.append([W[i - 8][j] ^ t[j] for j in range(4)])
    return [bytes(bytearray(b for w in W[4 * r:4 * r + 4] for b in w))
            for r in range(15)]


_RK = _key_schedule(SEED)
_MCM = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
ICM = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))


def _shift_rows(b):
    b = bytearray(b)
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r + c) % 4) + c]
    return bytes(out)


def _sr_inverse(b):
    b = bytearray(b)
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r - c) % 4) + c]
    return bytes(out)


def _mix_columns(b):
    b = bytearray(b)
    out = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= _gmul(col[j], _MCM[i][j])
            out[4 * q + i] = v
    return bytes(out)


def _mix(b, mat):
    b = bytearray(b)
    out = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= _gmul(col[j], mat[i][j])
            out[4 * q + i] = v
    return bytes(out)


def spn_chunk(P):
    x = bytes(bytearray(a ^ b for a, b in zip(bytearray(P),
                                          bytearray(_RK[0]))))
    x = bytes(bytearray(bytearray(AES_SBOX)[v]
                        for v in bytearray(x)))
    for r in range(13):
        x = _shift_rows(x)
        x = _mix_columns(x)
        x = bytes(bytearray(a ^ b for a, b in zip(bytearray(x),
                                              bytearray(_RK[1 + r]))))
        x = bytes(bytearray(bytearray(AES_SBOX)[v]
                        for v in bytearray(x)))
    x = _shift_rows(x)
    return bytes(bytearray(a ^ b for a, b in zip(bytearray(x),
                                               bytearray(_RK[14]))))


def cbc_encrypt(record, header):
    out, wa = b"", header
    for k in range(0, len(record), 16):
        c = spn_chunk(bytes(bytearray(a ^ b for a, b in
                                     zip(bytearray(record[k:k + 16]),
                                         bytearray(wa)))))
        out += c
        wa = c
    return out


def cbc_decrypt(body, header):
    """Independent inverse SPN -- proves the forward law inverts."""

    INV = bytearray(INVBOX)

    def spn_inv(C):
        y = _sr_inverse(bytes(bytearray(a ^ b for a, b in
                                       zip(bytearray(C),
                                           bytearray(_RK[14])))))
        for r in range(13, 0, -1):
            c = bytes(bytearray(INV[v] for v in bytearray(y)))
            b = bytes(bytearray(a ^ b for a, b in zip(bytearray(c),
                                                      bytearray(_RK[r]))))
            a = _mix(b, ICM)
            y = _sr_inverse(a)
        p = bytes(bytearray(INV[v] for v in bytearray(y)))
        return bytes(bytearray(a ^ b for a, b in zip(bytearray(p),
                                                     bytearray(_RK[0]))))

    out, prev = b"", header
    for k in range(0, len(body), 16):
        blk = body[k:k + 16]
        out += bytes(bytearray(a ^ b for a, b in
                                zip(bytearray(spn_inv(blk)),
                                    bytearray(prev))))
        prev = blk
    return out


# ------------------------------------------------------------------ sign
_STREAM = {}          # per-second MINSTD state: the device seeds once per
                      # second and ADVANCES per sign (the berain law)


def _stream_block(x):
    d = []
    for _ in range(8):
        x = (_A31 * x) % _M31
        d.append(x)
    w = [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return b"".join(struct.pack(">I", v) for v in w), x


def sign(second, nonce12, claims, advance=None):
    """The 304-byte blob.

    advance: None (default) = device behaviour: the header comes from the
    per-second MINSTD stream, seeded on the first sign of that second and
    ADVANCED (not reseeded) on every further sign within the same second.
    Proven on the berain capture row 045 (sdk_click): the second sign of
    second 1779250802 sits at stream step 1 while the first sign of that
    same second is step 0.
    advance=N = explicit override: seed fresh at the second and skip N
    further blocks (for minting a specific known blob).
    """
    sec = int(second)
    if advance is None:      # device behaviour (stream state)
        x = _STREAM.get(sec)
        if x is None:
            x = sec % _M31 or 1
        header, x = _stream_block(x)
        _STREAM[sec] = x
    else:                    # stateless: 0 = first block, N = N blocks ahead
        x = sec % _M31 or 1
        header = None
        for _ in range(int(advance) + 1):
            header, x = _stream_block(x)
    H = commitment_digest(claims, bytes(nonce12))
    record = build_record(H, bytes(nonce12))
    body = cbc_encrypt(record, header)
    return header + body + hmac.new(DK37, body, hashlib.sha256).digest()


def sign_request(fields, kind, second=None, nonce12=None, client_sdk="",
                 headers_id="8", native_version="3.62.0", advance=0):
    """Sign one request -> (Authorization header value, 304-B blob).

    headers_id / native_version are PER SDK BUILD (they ride in the auth
    header only, never in the blob):
        ios5.4.6 -> "7"  / "3.61.0"     ios5.5.0 -> "8" / "3.62.0"

    advance: stream step within the signing second (0 = first sign; 1+ =
    a later sign in the SAME second, which advances the MINSTD instead of
    reseeding -- the berain law).
    """
    if second is None:
        second = int(time.time())
    if nonce12 is None:
        nonce12 = os.urandom(12)
    claims = build_claims(kind, fields, client_sdk=client_sdk)
    blob = sign(second, nonce12, claims, advance=advance)
    auth = ('Signature signature="%s",adj_signing_id="%s",algorithm="%s",'
            'headers_id="%s",native_version="%s"'
            % (_hexup(blob), ADJ_SIGNING_ID, ALGORITHM, headers_id,
               native_version))
    return auth, blob


def verify_tag(blob):
    return hmac.compare_digest(
        hmac.new(DK37, blob[16:272], hashlib.sha256).digest(), blob[272:304])


# -------------------------------------------------------------- selftest
RECORD_RE = (b'\{ "a":  ([ 0-9]{20}) ,"b": "([0-9A-Fa-f]{64})","c": "'
             b'(.{40})","d": "([0-9A-Fa-f]{8})","e": "([0-9A-Fa-f]{64})" \}')
HERE = os.path.dirname(os.path.abspath(__file__))


def selftest():
    import re
    path = os.path.join(HERE, "gold_vectors.json")
    if not os.path.exists(path):
        print("gold_vectors.json missing -- run make_gold.py first")
        return False
    try:
        vectors = json.load(open(path, encoding="utf-8"))
    except TypeError:          # py2: open() has no encoding kwarg
        vectors = json.load(open(path))
    n_ok = 0
    for v in vectors:
        claims = build_claims(v["kind"], v["params"],
                              client_sdk=v["client_sdk"])
        blob = sign(v["second"],
                   binascii.unhexlify(v["nonce12"]), claims,
                   advance=0)
        if _hexup(blob) != v["sig"]:
            print("FAIL %s %s: mint != capture" % (v["capture"], v["sid"]))
            continue
        assert verify_tag(blob)
        rec = cbc_decrypt(blob[16:272], blob[:16])
        m = re.match(RECORD_RE, rec)
        assert m and rec.endswith(b"\x10" * 16) and m.group(3) == CERT40_IOS
        nonce12 = (struct.pack("<Q", int(m.group(1).decode().strip()))
                   + binascii.unhexlify(m.group(4).decode()))
        assert nonce12 == binascii.unhexlify(v["nonce12"])
        assert _hexup(commitment_digest(claims, nonce12)) \
            == m.group(2).decode()
        n_ok += 1
        print("ok %-7s sid %-3s %-20s sec=%d BYTE-EXACT"
              % (v["capture"], v["sid"], v["kind"], v["second"]))
    print("\n%d vectors, %d byte-exact (tag+decrypt+record+H re-verified)"
          % (len(vectors), n_ok))
    if n_ok != len(vectors):
        raise SystemExit(1)
    print("SELFTEST OK")
    return True


if __name__ == "__main__":
    selftest()
