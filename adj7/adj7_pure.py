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
                 00*40 || nonce12 || sha256('') hex-upper || claims
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


# ======================================================================
# PART 6 — frozen vectors + the selftest (python adj7_pure.py --selftest)
# ======================================================================
# The four recorded unicorn-mint blobs (A/B/C from the original mint run,
# D = commit2_fresh.py, sec 1771239000, app_version "7.7.7"), the genuine
# device signatures and the niri capture are the acceptance evidence for
# THE LAW.  Kept inline so the module stays self-contained (stdlib only)
# and the py27 build carries the same vectors.
_P0015 = {
    "android_uuid": "423d13f2-4a9f-40eb-b1e4-c292f53fa223",
    "api_level": "34",
    "app_token": "7k3pz7m9x79c",
    "app_version": "8.4.4",
    "attribution_deeplink": "1",
    "connectivity_type": "1",
    "country": "US",
    "cpu_type": "arm64-v8a",
    "created_at": "2026-09-14T16:17:02.965Z+0800",
    "device_manufacturer": "OnePlus",
    "device_name": "ONEPLUS A6013",
    "device_type": "phone",
    "display_height": "2193",
    "display_width": "1080",
    "enqueue_size": "0",
    "environment": "production",
    "first_error": "0",
    "foreground": "1",
    "gps_adid": "f29a6637-e6bf-437d-bd7e-e8eedf9510ec",
    "gps_adid_attempt": "1",
    "gps_adid_src": "service",
    "hardware_name": "AP1A.240505.005.B1",
    "initiating_package_name": "com.android.vending",
    "installed_at": "2026-09-14T16:16:32.314Z+0800",
    "language": "en",
    "last_error": "0",
    "needs_response_details": "1",
    "offline_mode_enabled": "0",
    "os_build": "AP1A.240505.005.B1",
    "os_name": "android",
    "os_version": "14",
    "package_name": "com.technologies.subtlelabs.doodhvale",
    "retry_count": "0",
    "screen_density": "high",
    "screen_format": "long",
    "screen_size": "normal",
    "sent_at": "2026-09-14T16:17:02.992Z+0800",
    "session_count": "1",
    "store_name_from_system": "com.android.vending",
    "tracking_enabled": "1",
    "ui_mode": "1",
    "updated_at": "2026-09-14T16:16:32.314Z+0800",
    "wait_time": "0.0",
    "wait_total": "0.0"
}
_MINT_NONCE = "d666bf3444ddccca7eada76a"
_V_A = "66e7ca6832cb9e2210a0eba90d27c4c2dc3aa42a2658c418ceb0b1ffa9cfee07c7fcfffbf175bffec144be9c3d34a9058b4332d7032a3682f3acedea498a61747f1fd026515b3385bac466c0534b7982b4d39118bfd6df28ca3917992b8631db7ad9ca9e506cc32da76271103b1a989c0270e39be5eecc34269e04278afc0ceec217d659b57a695c2552f76a8b3d971d2094531b3f628db991b24054a432cc0361549256e904edd45e9416fc1f98cc09725d9d4d4845cb1b9b1e40779c65f0a2494409abed2eb30975cb3d8148c64bdcf5bf8e67625839bad48c704612a2545a6142afa75d8a934318ed706c5ebcb5cb18846318a152639ad7f3b4745398e0958908f6deb64636bde3e3613b7340bc3a7d7c87599fa1b20c0c3cf6665207d320004a13591e12143aa8c59ea5eb1d4961"
_V_B = "536402b675f352462fd7eda55bdd189e00de75be92a250832798794431b970a8c7884763952719673f970eb76d710cfd84053bdc2d6efadd9cd60e32da617bf02b3813496fce0da384aeea6f16d07b7b2634d3f9dba232053780d33e5bd6dd6f39447eef7af15ff0707acbcf6fb10437cd2401146401f422ce82e7cbd9011647da100f686f4a37170e9b88cf99c6fb1c2f5b7b5431c9ba3d4c37cf6e00644146fcd4f1beca5968a294997f11e4bdaab36876908972c0f7086984addd037af70c97bd381203d9d47bb5b4bcfc9ece7b6297b281e43a034acb6655acf65f08fe64065391caf208dabe94e4769640df3507c797a39fcefb552617d33dfecb8c970c4ba5f07d054495fcdb3ad2737332181ccf4c87d72bba33505c8e425c7283d9bda5e2559d778e188b07f7f02853ba505b"
_V_C = "66e7ca6832cb9e2210a0eba90d27c4c2dc3aa42a2658c418ceb0b1ffa9cfee07c7fcfffbf175bffec144be9c3d34a905d69278e2a0134878e733ad54ffcc74f231bb6268d9aea499f5d7b24904b05ce6a794c71f09cbfbd9583adc73fd17517dad374ce05577a8389501a98e1833c50e7251bc61ef36ef8b08a4490ad520c6b3617fb44f1120f4c6f1afb08764002eda58ec085fc8ae171548bc365fcd5cf51d5017d927e5aa05400f99f8bbb67951ec04dfbc2cfcfe39ed74b45dafa87d248d695193494446d581284580245536f4938c8cb60dcc658d29c35745dc686788c9d6dd597202f397c2c9c3242308bf2f0844902ba02bde7ef66a6e1524e275757ee242d6481e5e310081b7c3a401e59b9267bc4ba9ad32be4ed32509edab1cd15d4c77fff85d3d489f6bf15897298de065"
_V_D = "223a2f7b4d190cbc4420d6cf44da5b344585c2e49e0661403f2d92ef785592d318f4d6d75155543f7a441c644c58b27a445c87ab66d2e5035b456d0a5ef75e6d6ca80e8ed26dd06e6fea7cd8b9a22fef0f291e5f2261558d15e52280ce46e47efe86e73a744fca08184bedd94e10d7741a80ba34b9409f95badfda7f4031fea031cd7aebb76f8f4e41682d104fb254712329d37d04831419983c55238ebbd58e83884777975a5c996f54233c83c71bc610e8fe0c873850e39b232e9901fa10cc8a297c3a4a43b8c8ade611fea4e450173f5997e2659da4dcadd9d47ccc08e62eef59345145a4efed88e1b307d6aab44a0fd25ec9dc38676e15b9b4754c30ff917d2d4cf6a38e18aa5d196718009817a3e17325163362b71931fc7fb0515d146936aaf1d1552072b29274872212ab5373"
_NIRI_SIG = "0C4106FC5D7CF6815F48EAA92C77D0D1454AB8CAA29E4B16A2B10F63CF59A74D9E2216B038DACFCA5F1C320CEB9DB54472ECD0CADD7BCF21EFD5547DB10AAA6B65B8C54D40C2364968D22F48EC3B87631D5C1574039E3CF88E317E754880D804D8D19960DCDD7AFF609E1BF0B4FCA2AD3988CCA9CF5C7F95AFC52830DF786D5DF3799959B83B92293891903C14726E81D089B7858B6B82B8759DBB88F25E34114F00119287B532F29E2B91ED4DAC6E0C3509ADF9716E07AFA49ADB257065CD7A4F78DC13D75F002B6BF7C09ABAE072FE701DE12F1B8CEF0B2BE8DD5AA0657693249FDB66497D76C05625C1D2756BCB5EBE7E202D7D65CF67C00CBF923C3F1BE75C503F81D054937AFF5F5EEC0559B507B6E2AC4DA6D1551F18926387B3AE8C376DC9042A5C7B961EE8EFE897185DDED2"
_HANA_SIG = "432A73E36247F58D0B4D16A60C4FD2804EDA1AB3F75DE1B102A5EB9BE22D68A5BB91FED656A31E268F12F592D530F8D61DEAC2A65C56322EAFBD1293F00CD933DB8E3408674EA3CD7EC408519ABF4067AD5EE0E8BE7847E102828C8BF70F7547F57B13D6F5EDEFD128D576A2E0A930C3886B2DF5009781440D936EDDF84B9DCD4C392923931D9E59894AB1CDA9B21284F5027E54A01664F10BAC6622ED459C7F4F98C52F93349D94824F98672EF0CF40163F1AB4A5B36EB5F502E062975C06A6F8B0676FF333DA73327EFFDB68BEFD8A16177B782A072484A0DC1B037D90E482D4A040CBB8AAF82B431D1337841EE81A4C978806A60E4952A91BB1C01F4706D2F8101A257322E622BE5DC4784BA87BE257FD058AE56319889EA4114F314DE26A50EE16918DAC6FF36469B732A7E7EB3D"

_NIRI_CAPTURE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "cap", "nirio_16Feb", "nirio_16Feb_oneplus7_newapp_adjust.json")


def selftest():
    """The documented `python adj7_pure.py --selftest` (py2/py3-safe):

      (a) reproduce the four frozen unicorn-mint blobs byte-exact,
      (b) tag law on the genuine device signatures (niri 3.61.0, hanaf
          3.62.0),
      (c) header law on the frozen mint heads,
      (d) tag + header laws over all 12 signed requests of the niri
          capture (present on disk; SKIP otherwise).

    Returns True on PASS."""
    import calendar
    import json as _json
    import re as _re
    from datetime import datetime as _dt, timedelta as _td

    ok = True
    nonce = bytes.fromhex(_MINT_NONCE)

    # (a) the frozen unicorn-mint blobs -- byte-exact
    for name, sec, over, want in (
            ("mint A", 1771238644, None, _V_A),
            ("mint B", 1771238645, None, _V_B),
            ("mint C", 1771238644, {"app_version": "9.9.9"}, _V_C),
            ("mint D", 1771239000, {"app_version": "7.7.7"}, _V_D)):
        p = dict(_P0015)
        if over:
            p.update(over)
        blob = sign(sec, nonce, build_claims("session", p), None)
        good = blob == bytes.fromhex(want)
        ok = ok and good
        print("[selftest] %s byte-exact  : %s"
              % (name, "OK" if good else "FAIL"))

    # (b) tag law on the genuine device signatures
    for name, sig in (("niri 3.61.0", _NIRI_SIG),
                      ("hanafintech 3.62.0", _HANA_SIG)):
        good = verify_tag(bytes.fromhex(sig))
        ok = ok and good
        print("[selftest] tag law %-18s: %s"
              % (name, "OK" if good else "FAIL"))

    # (c) header law on the frozen mint heads
    for name, sec, want in (("mint A", 1771238644, _V_A),
                            ("mint B", 1771238645, _V_B),
                            ("mint D", 1771239000, _V_D)):
        good = make_header(sec) == bytes.fromhex(want)[:16]
        ok = ok and good
        print("[selftest] header %-19s: %s"
              % (name, "OK" if good else "FAIL"))

    # (d) the genuine niri capture (12 signed requests)
    if os.path.exists(_NIRI_CAPTURE):
        def _to_sec(s):
            m = _re.match(r"(.*?)Z([+-][0-9]{4})?$", s)
            if not m:
                return None
            tz = m.group(2) or "+0000"
            d = None
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
                try:
                    d = _dt.strptime(m.group(1), fmt)
                    break
                except ValueError:
                    continue
            if d is None:
                return None
            sgn = 1 if tz[0] == "+" else -1
            d = d - _td(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sgn
            return calendar.timegm(d.timetuple()) + d.microsecond / 1e6

        tag_ok = head_ok = n = 0
        for r in _json.load(open(_NIRI_CAPTURE)):
            auth = next(v for k, v in r["request_headers"]
                        if k.lower() == "authorization")
            sig = _re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1)
            blob = bytes.fromhex(sig)
            n += 1
            tag_ok += 1 if verify_tag(blob) else 0
            cands = []
            if r.get("method") == "POST" and isinstance(r.get("body"), dict):
                for fld in ("created_at", "sent_at"):
                    if fld in r["body"]:
                        t = _to_sec(r["body"][fld])
                        if t is not None:
                            t = int(t)
                            cands += [t - 1, t, t + 1]
            if any(make_header(c) == blob[:16] for c in cands):
                head_ok += 1
        # documented header misses: sid 90 (signed in an earlier app
        # process, its head matches no second of the capture window) and
        # sid 96 (attribution GET carries no time field to seed from).
        print("[selftest] niri tag law %d/%d, header law %d/%d"
              % (tag_ok, n, head_ok, n))
        ok = ok and tag_ok == n and head_ok >= n - 2
    else:
        print("[selftest] niri capture     : SKIP (not found)")

    print("[selftest] SELFTEST %s" % ("OK" if ok else "FAILED"))
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if selftest() else 1)
    sys.stderr.write("usage: python %s --selftest\n" % sys.argv[0])
    sys.exit(2)
