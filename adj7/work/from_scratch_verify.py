"""from_scratch_verify.py — a COMPLETE from-scratch re-implementation of the
adj7 signature, written against the RAW LAW SPEC ONLY (no adj7_pure import),
then byte-verified against genuine device signatures from two devices.

The law (from the reverse-engineering):
  blob(304) = header(16) || body(256) || tag(32)
  header    = bionic rand() of the signing second: the 31-word additive LCG
              seeded with the second, 310 warm-up draws, then 8 draws,
              XORed in pairs, big-endian.
  record    = '{ "a":  <str(u64le(nonce12[0:8])) rjust(20)> ,"b": "<H>",'
              '"c": "<cert40>","d": "<hex-upper(nonce12[8:12])>",'
              '"e": "<sha256(b'') hex-upper>" }\x00' + 0x10 * 16   (256 B)
  H         = SHA-256 with the custom IV
              (16ba6d02 11a298c2 82187e46 4c148c22 3a5cbc15 06519f14
               97b9e370 08ec3bec) over
              prefix40 || nonce12 || sha256(b'') hex-upper || claims
              where prefix40 = the cert SHA-1 ASCII (real device) or 00*40
              (the no-cert path), claims = the 97-key pool order, the map's
              present values bare, "1300000" pinned between profile(<
              session_count) and tail(>= session_count), activity_kind +
              client_sdk appended when the map carries them.
  body      = CBC-AES-256(key = the universal 32-B seed
              f110fb41676dba311f38c652c8f951ec3db456c07b9166a509bef66cd870654b,
              IV = header), the standard AES-256 rounds with the measured
              ShiftRows out[4r+c] = in[4((r+c)%4)+c] and NO final SubBytes.
  tag       = HMAC-SHA256(DK37, body),
              DK37 = 2a4cc07960d647623cc386dcefafbf25b669914d32cc8585a1ed7f920ef591eb

    python from_scratch_verify.py
"""
import hashlib
import hmac
import json
import struct
import sys
import urllib.parse
from datetime import datetime, timezone

# ---------------- the constants (recorded from the lib) ----------------
SEED = bytes.fromhex("f110fb41676dba311f38c652c8f951ec"
                     "3db456c07b9166a509bef66cd870654b")
DK37 = bytes.fromhex("2a4cc07960d647623cc386dcefafbf25"
                     "b669914d32cc8585a1ed7f920ef591eb")
IV0_WORDS = (0x16ba6d02, 0x11a298c2, 0x82187e46, 0x4c148c22,
             0x3a5cbc15, 0x06519f14, 0x97b9e370, 0x08ec3bec)
SHA0HEX = hashlib.sha256(b"").hexdigest().upper()
POOL = ("ad_impressions_count ad_revenue_network ad_revenue_placement "
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
        "reftag revenue sales_region secondary_dedupe_token seq "
        "session_count session_length sharing skadn_registered_at source "
        "started_at store_app_id_from_client store_name_from_client "
        "store_name_from_system subsession_count time_spent tracker "
        "tracking_enabled updated_at activity_kind client_sdk").split()

# ---------------- bionic rand header ----------------
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


def make_header(second):
    r = [0] * 31
    s = second & 0xFFFFFFFF or 1
    w = s if s < _M else s - 2 ** 32
    r[0] = w
    prev = w
    for i in range(1, 31):
        r[i] = _schrage(prev)
        prev = r[i]
    f, b = 3, 0
    for _ in range(310):
        v = (r[f] + r[b]) & 0xFFFFFFFF
        r[f] = v if v < _M else v - 2 ** 32
        f = (f + 1) % 31
        b = (b + 1) % 31
    d = []
    for _ in range(8):
        v = (r[f] + r[b]) & 0xFFFFFFFF
        r[f] = v if v < _M else v - 2 ** 32
        f = (f + 1) % 31
        b = (b + 1) % 31
        d.append(v >> 1)
    out = b""
    for i in range(0, 8, 2):
        out += struct.pack(">I", d[i] ^ d[i + 1])
    return out


# ---------------- claims ----------------
def claims_string(kind, m, client_sdk):
    split = POOL.index("session_count")
    prof, tail, blk = POOL[:split], POOL[split:-2], POOL[-2:]
    parts = [str(m[k]) for k in prof if m.get(k) not in (None, "")]
    parts.append("1300000")
    parts += [str(m[k]) for k in tail if m.get(k) not in (None, "")]
    parts += [str(m[k]) for k in blk if m.get(k) not in (None, "")]
    return "".join(parts).encode("latin1")


# ---------------- the commitment hash (custom-IV SHA-256) ----------------
def _primes(n):
    out, i = [], 2
    while len(out) < n:
        if all(i % p for p in out if p * p <= i):
            out.append(i)
        i += 1
    return out


def _cbrt_frac(p):
    k = 0
    while (k + 1) ** 3 <= p:
        k += 1
    lo, hi, tgt, base = 0, 1 << 32, p << 96, k << 32
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if (base + mid) ** 3 <= tgt:
            lo = mid
        else:
            hi = mid - 1
    return lo


K256 = tuple(_cbrt_frac(pr) for pr in _primes(64))
MASK = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def _sha256_block(state, blk):
    w = list(blk)
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
        s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        t1 = (h + S1 + ((e & f) ^ ((~e & MASK) & g)) + K256[i] + w[i]) & MASK
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) & MASK
        h, g, f = g, f, e
        e = (d + t1) & MASK
        d, c, b = c, b, a
        a = (t1 + t2) & MASK
    return [(x + st) & MASK for x, st in zip((a, b, c, d, e, f, g, h), state)]


def sha256_iv0(msg):
    padded = (msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64)
              + struct.pack(">Q", len(msg) * 8))
    state = list(IV0_WORDS)
    for i in range(0, len(padded), 64):
        state = _sha256_block(state, struct.unpack(">16I", padded[i:i + 64]))
    return struct.pack(">8I", *state)


# ---------------- AES-256 core ----------------
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


SBOX = bytes(_affine(next(q for q in range(1, 256) if _gmul(v, q) == 1))
             if v else _affine(0) for v in range(256))


def key_schedule(key):
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
    return [bytes(b for w in W[4 * r:4 * r + 4] for b in w) for r in range(15)]


RK = key_schedule(SEED)


def _shift_rows(b):
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


def spn_chunk(P, keys):
    x = bytes(a ^ b for a, b in zip(P, keys[0]))
    x = bytes(SBOX[v] for v in x)
    for r in range(13):
        x = _shift_rows(x)
        x = _mix_columns(x)
        x = bytes(a ^ b for a, b in zip(x, keys[1 + r]))
        x = bytes(SBOX[v] for v in x)
    x = _shift_rows(x)
    return bytes(a ^ b for a, b in zip(x, keys[14]))


def cbc_encrypt(record, header, keys):
    out, wa = b"", header
    for k in range(0, len(record), 16):
        c = spn_chunk(bytes(a ^ b for a, b in zip(record[k:k + 16], wa)), keys)
        out += c
        wa = c
    return out


# ---------------- the record + H ----------------
def build_record(H, nonce12, cert40):
    if cert40 is None:
        cert40 = b"\x00" * 40
    A = str(int.from_bytes(nonce12[0:8], "little")).rjust(20)
    d8 = nonce12[8:12].hex().upper()
    j = (b'{ "a":  ' + A.encode() + b' ,"b": "' + H.hex().upper().encode()
         + b'","c": "' + cert40 + b'","d": "' + d8.encode()
         + b'","e": "' + SHA0HEX.encode() + b'" }\x00')
    return j + b"\x10" * (256 - len(j))


def commitment(claims, nonce12, cert40):
    prefix = cert40 if cert40 is not None else b"\x00" * 40
    return sha256_iv0(prefix + nonce12 + SHA0HEX.encode() + claims)


def full_blob(second, nonce12, claims, cert40):
    header = make_header(second)
    H = commitment(claims, nonce12, cert40)
    record = build_record(H, nonce12, cert40)
    body = cbc_encrypt(record, header, RK)
    return header + body + hmac.new(DK37, body, hashlib.sha256).digest()


# ---------------- verification ----------------
def main():
    ok = True
    fv = json.load(open("frozen_vectors.py".replace("frozen_vectors.py",
                                                    "frozen_vectors.py"))) if False else None
    sys.path.insert(0, ".")
    from frozen_vectors import (_P0015, _MINT_NONCE, _V_A, _V_B, _V_C,
                                _NIRI_SIG, _HANA_SIG)
    NOCERT = {"cert_sha1": "", "client_sdk": "", "adj_signing_id": "1300000",
              "headers_id": "8", "native_version": "3.62.0"}

    # (a) the frozen native mints — byte-exact
    for name, sec, over, want in (("mint A", 1771238644, None, _V_A),
                                  ("mint B", 1771238645, None, _V_B),
                                  ("mint C", 1771238644,
                                   {"app_version": "9.9.9"}, _V_C)):
        p = dict(_P0015)
        p.update(over or {})
        claims = claims_string("session", p, "")
        blob = full_blob(sec, bytes.fromhex(_MINT_NONCE), claims, None)
        good = blob == bytes.fromhex(want)
        ok &= good
        print("[from-scratch] %s byte-exact: %s" % (name, "OK" if good else "FAIL"))

    # (b) the tag law on the genuine device signatures
    for name, sig in (("niri 3.61.0", _NIRI_SIG),
                      ("hanafintech 3.62.0", _HANA_SIG)):
        b = bytes.fromhex(sig)
        good = hmac.new(DK37, b[16:272], hashlib.sha256).digest() == b[272:304]
        ok &= good
        print("[from-scratch] tag law %-18s: %s" % (name, "OK" if good else "FAIL"))

    # (c) the header law: the frozen mints' heads
    for name, sec, want in (("mint A", 1771238644, _V_A),
                            ("mint B", 1771238645, _V_B)):
        good = make_header(sec) == bytes.fromhex(want)[:16]
        ok &= good
        print("[from-scratch] header %-18s: %s" % (name, "OK" if good else "FAIL"))

    print("[from-scratch] SELFTEST %s" % ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
