"""audit_reimpl.py -- a FRESH, independent re-implementation of the adj7
304-B signature blob, written directly from the stated laws WITHOUT
importing adj7_pure (or any adj7 module), then checked byte-exact against
the frozen recorded mint vector _V_A (adj7/work/frozen_vectors.py:
_P0015 body params, _MINT_NONCE = d666bf3444ddccca7eada76a, signing
second 1771238644).

Laws implemented here (independently re-derived code, not copied):

  blob(304) = header(16) || body(256) || tag(32)
  header    bionic rand() of the signing second: 31-word Lehmer state
            (a=16807, m=2**31-1, Schrage), taps r[3]+r[0], 310-draw
            warm-up, 8 draws, pair-XOR, big-endian.
  claims    the native's claim pool in pool order, present (non-empty)
            values concatenated bare, pinned "1300000" emitted between
            the profile group (< "session_count") and the tail group;
            block2 (activity_kind, client_sdk) appended when carried.
  H         sha256 with custom IV0 over
              prefix || nonce12 || hex-upper(sha256(b"")) || claims
            prefix = cert SHA-1 as 40 ASCII bytes when a cert is set,
            else 00*40.
  record    '{ "a":  <A> ,"b": "<H>","c": "<cert40>","d": "<D8>",
              "e": "<sha256('') hex-upper>" }' + NUL + 0x10-fill to 256
            A = str(u64-LE nonce12[0:8]) right-justified to 20 chars,
            D8 = hex-upper(nonce12[8:12]).
  body      CBC (IV = header) over the record with AES-256:
            textbook key schedule of SEED, ShiftRows
            out[4r+c] = in[4((r+c)%4)+c], MixColumns standard,
            round loop ARK K0, SB, 13 x [SR, MC, ARK, SB], SR, ARK K14
            -- NO final SubBytes.
  tag       HMAC-SHA256(DK37, body).

VERDICT (this run): printed at the bottom -- byte-equality with _V_A.

    python audit_reimpl.py
"""
import hashlib
import hmac
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, ".."))

# ---------------------------------------------------------------- recorded
SEED = bytes.fromhex("f110fb41676dba311f38c652c8f951ec"
                     "3db456c07b9166a509bef66cd870654b")
DK37 = bytes.fromhex("2a4cc07960d647623cc386dcefafbf25"
                     "b669914d32cc8585a1ed7f920ef591eb")
IV0_HEX = "16ba6d0211a298c282187e464c148c22" \
          "3a5cbc1506519f1497b9e37008ec3bec"
PIN = "1300000"

CLAIM_POOL = [
    "ad_impressions_count", "ad_revenue_network", "ad_revenue_placement",
    "ad_revenue_unit", "adgroup", "android_id", "android_uuid", "api_level",
    "app_secret", "app_token", "app_version", "app_version_short",
    "att_status", "bundle_id", "callback_params", "campaign", "click_time",
    "click_time_server", "country", "created_at", "creative", "currency",
    "deduplication_id", "default_tracker", "details", "device_known",
    "device_name", "device_type", "environment", "event_callback_id",
    "event_count", "event_token", "external_device_id", "fb_anon_id",
    "fb_id", "ff_app_set_id_disabled", "ff_att_disabled", "ff_idfv_disabled",
    "ff_odm_enabled", "fire_adid", "fire_tracking_enabled",
    "found_location", "google_play_instant", "gps_adid", "gps_adid_src",
    "granular_third_party_sharing_options", "hardware_name", "idfa", "idfv",
    "initiated_by", "initiating_package_name", "install_begin_time",
    "install_begin_time_server", "install_version", "installed_at",
    "last_skan_update", "mcc", "measurement", "mnc", "needs_cost",
    "odm_info", "order_id", "originating_package_name", "os_build",
    "os_name", "os_version", "package_name", "params", "partner_params",
    "partner_sharing_settings", "payload", "primary_dedupe_token",
    "purchase_time", "push_token", "referrer", "referrer_api", "reftag",
    "revenue", "sales_region", "secondary_dedupe_token", "secret_id", "seq",
    "session_count", "session_length", "sharing", "skadn_registered_at",
    "source", "started_at", "store_app_id_from_client",
    "store_name_from_client", "store_name_from_system", "subsession_count",
    "time_spent", "tracker", "tracking_enabled", "updated_at",
    "activity_kind", "client_sdk",
]

# =================================================================
# header -- bionic rand()
# =================================================================
_M = (1 << 31) - 1
_A = 16807
_Q, _R = _M // _A, _M % _A


def _schrage(prev):
    if prev >= 0:
        hi, lo = divmod(prev, _Q)
    else:
        hi = -((-prev) // _Q)
        lo = prev - hi * _Q
    y = lo * _A - hi * _R
    return y + _M if y < 0 else y


def make_header(unix_sec):
    s = int(unix_sec) & 0xFFFFFFFF or 1
    w = s if s < 2 ** 31 else s - 2 ** 32
    st = [w] + [0] * 30
    for i in range(1, 31):
        st[i] = _schrage(st[i - 1])
    f, b = 3, 0
    draws = []
    for k in range(310 + 8):
        v = (st[f] + st[b]) & 0xFFFFFFFF
        st[f] = v if v < 2 ** 31 else v - 2 ** 32
        f = (f + 1) % 31
        b = (b + 1) % 31
        if k >= 310:
            draws.append(v >> 1)
    out = b"".join(struct.pack(">I", draws[2 * i] ^ draws[2 * i + 1])
                   for i in range(4))
    return out


# =================================================================
# SHA-256 constants from cube roots of the first 64 primes (exact ints)
# =================================================================
def _primes(n):
    out, i = [], 2
    while len(out) < n:
        if all(i % p for p in out if p * p <= i):
            out.append(i)
        i += 1
    return out


def _icbrt(n):
    """floor(n ** (1/3)) in exact integers (Newton from above, then
    clamped down to the exact floor)."""
    if n < 2:
        return n
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            break
        x = y
    while x * x * x > n:
        x -= 1
    while (x + 1) ** 3 <= n:
        x += 1
    return x


def _frac_cbrt_2p32(p):
    """floor(frac(cbrt(p)) * 2**32): cbrt(p * 2**96) = cbrt(p) * 2**32,
    and floor(cbrt(p)*2**32) = floor(cbrt(p))*2**32 + the fraction part."""
    return _icbrt(p << 96) - (_icbrt(p) << 32)


K256 = [_frac_cbrt_2p32(p) for p in _primes(64)]


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def sha256_custom_iv(msg, iv):
    """SHA-256 compression with a caller-supplied 32-B IV, standard
    padding/constants/rounds otherwise."""
    st = list(struct.unpack(">8I", iv))
    m = (msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64)
         + struct.pack(">Q", len(msg) * 8))
    for blk in range(0, len(m), 64):
        w = list(struct.unpack(">16I", m[blk:blk + 64]))
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, h = st
        for i in range(64):
            S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            t1 = (h + S1 + ((e & f) ^ (~e & g)) + K256[i] + w[i]) & 0xFFFFFFFF
            S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) & 0xFFFFFFFF
            h, g, f, e = g, f, e, (d + t1) & 0xFFFFFFFF
            d, c, b, a = c, b, a, (t1 + t2) & 0xFFFFFFFF
        st = [(x + y) & 0xFFFFFFFF
              for x, y in zip(st, (a, b, c, d, e, f, g, h))]
    return struct.pack(">8I", *st)


# =================================================================
# claims
# =================================================================
def build_claims(params, activity_kind=None, client_sdk=None):
    """Pool-order claims: profile values, the pinned signing id, tail
    values, then block2 (activity_kind/client_sdk) when carried."""
    m = dict(params)
    if activity_kind is not None:
        m.setdefault("activity_kind", activity_kind)
    if client_sdk is not None:
        m.setdefault("client_sdk", client_sdk)
    split = CLAIM_POOL.index("session_count")
    profile, tail, block2 = CLAIM_POOL[:split], CLAIM_POOL[split:-2], \
        CLAIM_POOL[-2:]
    parts = [str(m[k]) for k in profile if m.get(k) not in (None, "")]
    parts.append(PIN)
    parts += [str(m[k]) for k in tail if m.get(k) not in (None, "")]
    parts += [str(m[k]) for k in block2 if m.get(k) not in (None, "")]
    return "".join(parts).encode("latin1")


def commitment_digest(claims, nonce12, cert40=None):
    prefix = cert40 if cert40 is not None else b"\x00" * 40
    msg = (prefix + nonce12
           + hashlib.sha256(b"").hexdigest().upper().encode() + claims)
    return sha256_custom_iv(msg, bytes.fromhex(IV0_HEX))


def build_record(H, nonce12, cert40=None):
    if cert40 is None:
        cert40 = b"\x00" * 40
    a = str(int.from_bytes(nonce12[0:8], "little")).rjust(20)
    d8 = nonce12[8:12].hex().upper()
    e64 = hashlib.sha256(b"").hexdigest().upper()
    j = (b'{ "a":  ' + a.encode() + b' ,"b": "' + H.hex().upper().encode()
         + b'","c": "' + cert40 + b'","d": "' + d8.encode()
         + b'","e": "' + e64.encode() + b'" }\x00')
    return j + b"\x10" * (256 - len(j))


# =================================================================
# AES-256 core (standard tables; measured ShiftRows; no final SubBytes)
# =================================================================
AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")


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


def key_schedule(key):
    """Textbook AES-256 expansion -> 15 round keys K0..K14."""
    W = [list(key[4 * i:4 * i + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(W[i - 1])
        if i % 8 == 0:
            t = t[1:] + t[:1]                      # RotWord
            t = [AES_SBOX[b] for b in t]           # SubWord
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [AES_SBOX[b] for b in t]           # SubWord
        W.append([W[i - 8][j] ^ t[j] for j in range(4)])
    return [bytes(b for w in W[4 * r:4 * r + 4] for b in w)
            for r in range(15)]


KEYS = key_schedule(SEED)


def shift_rows(b):
    """Measured law: new M[r][c] = old M[(r+c) % 4][c]."""
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r + c) % 4) + c]
    return bytes(out)


_MCM = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))


def mix_columns(b):
    out = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= _gmul(col[j], _MCM[i][j])
            out[4 * q + i] = v
    return bytes(out)


def spn_block(P):
    """ARK K0, SB, 13 x [SR, MC, ARK, SB], SR, ARK K14 -- no final SB."""
    x = bytes(a ^ b for a, b in zip(P, KEYS[0]))
    x = bytes(AES_SBOX[v] for v in x)
    for r in range(1, 14):
        x = mix_columns(shift_rows(x))
        x = bytes(a ^ b for a, b in zip(x, KEYS[r]))
        x = bytes(AES_SBOX[v] for v in x)
    x = shift_rows(x)
    return bytes(a ^ b for a, b in zip(x, KEYS[14]))


def cbc_encrypt(record, iv):
    out, prev = b"", iv
    for k in range(0, len(record), 16):
        prev = spn_block(bytes(a ^ b for a, b in zip(record[k:k + 16], prev)))
        out += prev
    return out


# =================================================================
# the blob
# =================================================================
def mint(params, second, nonce12, cert40=None, activity_kind=None,
         client_sdk=None):
    header = make_header(second)
    claims = build_claims(params, activity_kind, client_sdk)
    H = commitment_digest(claims, nonce12, cert40)
    record = build_record(H, nonce12, cert40)
    body = cbc_encrypt(record, header)
    return header + body + hmac.new(DK37, body, hashlib.sha256).digest()


def main():
    ns = {}
    with open(os.path.join(WORK, "frozen_vectors.py")) as fh:
        exec(fh.read(), ns)             # data only; no adj7 module involved
    p0015 = ns["_P0015"]
    nonce = bytes.fromhex(ns["_MINT_NONCE"])
    v_a = ns["_V_A"].upper()
    sec = 1771238644                    # the recorded signing second

    blob = mint(p0015, sec, nonce)      # mint path: no cert, no block2
    got = blob.hex().upper()

    print("audit_reimpl -- fresh adj7 blob from the laws (no adj7_pure)")
    print("  inputs : _P0015 (%d fields), nonce %s, second %d,"
          " cert 00*40, block2 off"
          % (len(p0015), ns["_MINT_NONCE"], sec))
    print("  minted : %s..." % got[:64])
    print("  _V_A   : %s..." % v_a[:64])
    ok = got == v_a
    print("  BYTE-EQUAL to _V_A: %s" % ("YES" if ok else "NO"))
    if not ok:
        ref = bytes.fromhex(v_a)
        diffs = [i for i in range(304) if blob[i] != ref[i]]
        print("  first diff at byte %d (header eq: %s, body eq: %s,"
              " tag eq: %s)"
              % (diffs[0], blob[:16] == ref[:16],
                 blob[16:272] == ref[16:272], blob[272:] == ref[272:]))
        sys.exit(1)

    # structure sanity on the matched blob
    print("  header == make_header(%d): %s" % (sec, blob[:16] ==
                                               make_header(sec)))
    print("  tag    == HMAC-SHA256(DK37, body): %s"
          % (hmac.new(DK37, blob[16:272], hashlib.sha256).digest()
             == blob[272:]))
    # and the same vector recorded on disk as blob_A/v3_blob/v4_blob
    for name in ("blob_A", "v3_blob", "v4_blob"):
        with open(os.path.join(WORK, name + ".hex")) as fh:
            print("  %s.hex == _V_A: %s"
                  % (name, fh.read().strip().upper() == v_a))
    print("VERDICT: PASS -- independent re-implementation reproduces _V_A"
          " byte-exact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
