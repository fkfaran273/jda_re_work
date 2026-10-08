"""adj7_pure.py -- the Adjust adj7 signature (algorithm "adj7", Adjust
Signature SDK 3.6x) in pure Python.  Stdlib only, no VM, no unicorn.

    blob(304) = header(16) || body(256) || tag(32)

  header  bionic rand() of the signing second: 310-draw warm-up, 8 draws,
          pair-XOR, big-endian.  (iOS native_variant would use MINSTD.)
  body    CBC over a 256-B JSON record with the 16-B header as IV:
            record = '{ "a":  <A> ,"b": "<H>" ,"c": "<cert40>","d": "<D8>",
                       "e": "<sha256('') hex-upper>" }\x00' + 0x10 * 16
            A  = str(u64le(nonce12[0:8])) right-justified to 20 chars
            D8 = hex-upper(nonce12[8:12]);  nonce12 = per-signing 12-B nonce
                 (random on a device; self-chosen here)
            cert40 = the app signing-cert SHA-1 as 40 hex chars -- OR 40 NUL
                 bytes on the emulator's no-cert path
            H  = sha256 with custom IV (IV0 below) over
                 cert40-ASCII || nonce12 || sha256('') hex-upper || claims
          cipher = AES-256 (standard SubBytes / ShiftRows / MixColumns),
          14 rounds, NO final SubBytes:  out = SR(s13) ^ K14, keys = the
          textbook AES-256 expansion of the generation seed SEED below.
  tag     HMAC-SHA256(DK37, blob[16:272]).

  claims  the native's 98-key claim pool, pool order, present values
          concatenated bare, pinned adj_signing_id ("1300000") emitted
          between the profile and tail groups (split at "seq");
          activity_kind/client_sdk append at the end when the signed map
          carries them (Java's d.sign adds both before nSign -- the wire
          filters them out).

  RECORDED constants (lib-generation constants, no generating rule known):
  SEED (the AES-256 key), DK37 (tag key), IV0 (commitment-hash IV), the
  claim pool.  Byte-exact vs genuine 3.62.0 blobs (unicorn mints) AND
  genuine 3.61.0 device captures (niri, OnePlus 7): both invert/verify
  under this exact law.

  USE
    import adj7_pure as sg
    blob, auth = sg.sign_request(fields, "session",
                                 cert_sha1="0E11...", second=sec)
    # cert_sha1 = the app's signing-cert SHA-1 (hex); None -> 40 NULs
    python adj7_pure.py --selftest
"""
import hashlib
import hmac
import os
import struct
import sys
import time

# ======================================================================
# PART 0 — recorded constants
# ======================================================================
SEED = bytes.fromhex(
    "f110fb41676dba311f38c652c8f951ec"
    "3db456c07b9166a509bef66cd870654b")          # AES-256 key (generation-wide)
DK37 = bytes.fromhex(
    "2a4cc07960d647623cc386dcefafbf25"
    "b669914d32cc8585a1ed7f920ef591eb")          # tag MAC key
IV0 = (0x16ba6d02, 0x11a298c2, 0x82187e46, 0x4c148c22,
       0x3a5cbc15, 0x06519f14, 0x97b9e370, 0x08ec3bec)   # commitment-hash IV
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

SHA0 = hashlib.sha256(b"").digest()
SHA0_HEX = SHA0.hex().upper()

# ======================================================================
# PART 1 — header (bionic rand, seed = signing second)
# ======================================================================
_M, _A = 2147483647, 16807
_Q, _R = _M // _A, _M % _A


def _schrage(prev):
    if prev >= 0:
        hi, lo = divmod(prev, _Q)
    else:
        hi = -((-prev) // _Q)
        lo = prev - hi * _Q
    y = lo * _A - hi * _R
    return y + _M if y < 0 else y


class BionicRand:
    """bionic rand(): 31-word additive LCG + 310-draw warm-up."""

    def __init__(self, seed):
        r = self.r = [0] * 31
        s = seed & 0xFFFFFFFF or 1
        w = s if s < 2 ** 31 else s - 2 ** 32
        r[0] = w
        prev = w
        for i in range(1, 31):
            r[i] = _schrage(prev)
            prev = r[i]
        self.f, self.b = 3, 0
        for _ in range(310):
            self.next()

    def next(self):
        v = (self.r[self.f] + self.r[self.b]) & 0xFFFFFFFF
        self.r[self.f] = v if v < _M else v - 2 ** 32
        self.f = (self.f + 1) % 31
        self.b = (self.b + 1) % 31
        return v >> 1


def make_header(unix_sec):
    R = BionicRand(int(unix_sec))
    d = [R.next() for _ in range(8)]
    w = [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return b"".join(v.to_bytes(4, "big") for v in w)


# ======================================================================
# PART 2 — claims
# ======================================================================
def build_claims(kind, params, client_sdk=None, include_block2=False):
    m = dict(params)
    if include_block2:
        m.setdefault("activity_kind", kind)
        m.setdefault("client_sdk", client_sdk or "")
    split = CLAIM_POOL.index("seq")
    # pin "1300000" is emitted before the seq value (pool audit: the event
    # map carries seq=1, which breaks the session_count degeneracy and proves
    # the slot; maps without seq are byte-identical either way).
    profile, tail, block2 = CLAIM_POOL[:split], CLAIM_POOL[split:-2], CLAIM_POOL[-2:]
    parts = [str(m[k]) for k in profile if m.get(k) not in (None, "")]
    parts.append(ADJ_SIGNING_ID)
    parts += [str(m[k]) for k in tail if m.get(k) not in (None, "")]
    parts += [str(m[k]) for k in block2 if m.get(k) not in (None, "")]
    return "".join(parts).encode("latin1")


# ======================================================================
# PART 3 — the commitment hash (sha256, custom IV0) and the record
# ======================================================================
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
M = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M


def _sha256_block(state, blk):
    w = list(blk)
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
        s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & M)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        t1 = (h + s1 + ((e & f) ^ ((~e & M) & g)) + _K256[i] + w[i]) & M
        s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        t2 = (s0 + ((a & b) ^ (a & c) ^ (b & c))) & M
        h, g, f = g, f, e
        e = (d + t1) & M
        d, c, b = c, b, a
        a = (t1 + t2) & M
    return [(x + st) & M for x, st in zip((a, b, c, d, e, f, g, h), state)]


def sha256_iv0(msg):
    """sha256 with the recorded custom IV0, standard padding."""
    padded = (msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64)
              + struct.pack(">Q", len(msg) * 8))
    state = list(IV0)
    for i in range(0, len(padded), 64):
        state = _sha256_block(state, struct.unpack(">16I", padded[i:i + 64]))
    return struct.pack(">8I", *state)


def commitment_digest(claims, nonce12, cert40=None):
    """H over 00*40||nonce12||sha0hex||claims on the emulator's no-cert
    path; on a real device (signing cert present) the 40-byte prefix is
    the cert SHA-1 ASCII itself (== the record's "c" slot content)."""
    prefix = cert40 if cert40 is not None else b"\x00" * 40
    msg = (prefix + nonce12 + SHA0_HEX.encode() + claims)
    return sha256_iv0(msg)


def build_record(H, nonce12, cert40=None):
    """The 256-B plaintext record.  cert40: 40 bytes -- the hex-upper cert
    SHA-1 of the app (real device) or 40 NUL bytes (no-cert path)."""
    if cert40 is None:
        cert40 = b"\x00" * 40
    A = str(int.from_bytes(nonce12[0:8], "little")).rjust(20)
    d8 = nonce12[8:12].hex().upper()
    j = (b'{ "a":  ' + A.encode() + b' ,"b": "' + H.hex().upper().encode()
         + b'","c": "' + cert40 + b'","d": "' + d8.encode()
         + b'","e": "' + SHA0_HEX.encode() + b'" }\x00')
    return j + b"\x10" * (256 - len(j))


# ======================================================================
# PART 4 — AES-256 core (standard; measured ShiftRows law; no final SBOX)
# ======================================================================
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
    return y ^ _rotl8(y, 1) ^ _rotl8(y, 2) ^ _rotl8(y, 3) ^ _rotl8(y, 4) ^ 0x63


AES_SBOX = bytes(_affine(next(q for q in range(1, 256) if _gmul(v, q) == 1))
                 if v else _affine(0) for v in range(256))


def _key_schedule(key):
    W = [list(key[i * 4:i * 4 + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(W[i - 1])
        if i % 8 == 0:
            t = [AES_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [AES_SBOX[b] for b in t]
        W.append([W[i - 8][j] ^ t[j] for j in range(4)])
    return [bytes(b for w in W[4 * r:4 * r + 4] for b in w) for r in range(15)]


_RK = _key_schedule(SEED)


def _shift_rows(b):
    """measured 0x1168 law: new M[r][c] = old M[(r+c) % 4][c]"""
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r + c) % 4) + c]
    return bytes(out)


_MCM = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))


def _mix_columns(b):
    out = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= _gmul(col[j], _MCM[i][j])
            out[4 * q + i] = v
    return bytes(out)


def spn_chunk(P, keys=_RK):
    x = bytes(a ^ b for a, b in zip(P, keys[0]))
    x = bytes(AES_SBOX[v] for v in x)
    for r in range(13):
        x = _shift_rows(x)
        x = _mix_columns(x)
        x = bytes(a ^ b for a, b in zip(x, keys[1 + r]))
        x = bytes(AES_SBOX[v] for v in x)
    x = _shift_rows(x)
    return bytes(a ^ b for a, b in zip(x, keys[14]))


def cbc_encrypt(record, header, keys=_RK):
    out, wa = b"", header
    for k in range(0, len(record), 16):
        c = spn_chunk(bytes(a ^ b for a, b in zip(record[k:k + 16], wa)),
                      keys)
        out += c
        wa = c
    return out


# ======================================================================
# PART 5 — the signature
# ======================================================================
def sign(second, nonce12, claims, cert40=None, keys=_RK):
    header = make_header(int(second))
    H = commitment_digest(claims, nonce12, cert40)
    record = build_record(H, nonce12, cert40)
    body = cbc_encrypt(record, header, keys)
    return header + body + hmac.new(DK37, body, hashlib.sha256).digest()


def sign_request(fields, kind, second=None, nonce12=None, cert_sha1=None,
                 client_sdk=None, include_block2=False,
                 adj_signing_id=ADJ_SIGNING_ID, headers_id="8",
                 native_version="3.62.0", campaign=None):
    """campaign (dict) overrides everything per-app when passed:
    {cert_sha1, client_sdk, adj_signing_id, headers_id, native_version} --
    the runner passes ITS campaign dict directly so no global wiring can be
    forgotten."""
    """Sign one request -> the Authorization header VALUE.

    fields        the wire map (str -> str)
    kind          session | click | event | attribution
    second        signing second (default: now)
    nonce12       12-B nonce; None -> urandom (device behaviour)
    cert_sha1     the app cert SHA-1 hex (40 chars) or None -> 40 NULs
    include_block2  True adds activity_kind+client_sdk to the claims
                  (the genuine Java path does; the mint path did not)
    campaign       dict overriding the per-app constants (cert_sha1,
                   client_sdk, adj_signing_id, headers_id, native_version)
    """
    if campaign:
        cert_sha1 = campaign.get("cert_sha1", cert_sha1)
        client_sdk = campaign.get("client_sdk", client_sdk)
        adj_signing_id = campaign.get("adj_signing_id", adj_signing_id)
        headers_id = campaign.get("headers_id", headers_id)
        native_version = campaign.get("native_version", native_version)
    if second is None:
        second = int(time.time())
    if nonce12 is None:
        nonce12 = os.urandom(12)
    claims = build_claims(kind, fields, client_sdk=client_sdk,
                          include_block2=include_block2)
    cert40 = cert_sha1.upper().encode() if cert_sha1 else None
    blob = sign(int(second), bytes(nonce12), claims, cert40)
    return ('Signature signature="%s",adj_signing_id="%s",algorithm="%s",'
            'headers_id="%s",native_version="%s"'
            % (blob.hex().upper(), adj_signing_id, ALGORITHM, headers_id,
               native_version))


def verify_tag(blob):
    return hmac.new(DK37, blob[16:272], hashlib.sha256).digest() == blob[272:304]


# per-campaign config (the funnel runner sets CERT_SHA1 from apps.json)
CERT_SHA1 = None          # 40-hex app signing-cert SHA-1; None -> 40 NULs
CLIENT_SDK = None         # campaign client_sdk (only used with block2)


def mint_adj7(kind, params, unix_sec=None, client_sdk=None,
              include_block2=False, nonce12=None, campaign=None):
    """Sign one request -> the Authorization header VALUE (the 304-B blob
    rides inside it as upper hex).

    campaign (dict) = the per-app constants passed straight through
    {cert_sha1, client_sdk, adj_signing_id, headers_id, native_version};
    the module globals CERT_SHA1/CLIENT_SDK are the fallback defaults.
    include_block2=True adds activity_kind+client_sdk to the claims (the
    genuine Java d.sign path).  Default False = the proven mint path.
    """
    return sign_request(
        params, kind, second=unix_sec, nonce12=nonce12,
        cert_sha1=CERT_SHA1 if CERT_SHA1 else None,
        client_sdk=client_sdk or CLIENT_SDK,
        include_block2=include_block2, campaign=campaign)
