"""spn_law2.py — adj7 (3.62.0) body[0:256], FULLY closed form, zero unicorn.

    body = CBC-AES-256(IV = header, plaintext = record, keys)

  keys   : standard AES-256 expansion (textbook: RotWord+SubWord+Rcon at
           i%8==0, SubWord at i%8==4, plain XOR otherwise) of the 32-B seed
           f110fb41676dba311f38c652c8f951ec3db456c07b9166a509bef66cd870654b
           (a generation constant, like DK37; universal across 3.61/3.62,
           emulator and device).  K_r = words W[4r..4r+3].
  record : 256-B JSON
             `{ "a":  <A> ,"b": "<H>","c": "<C40>","d": "<D8>","e": "<E64>" }`
           + 0x00 + 0x10-fill to 256, where
             A  = str(u64-LE of nonce12[0:8]) right-aligned in 20 chars
             D8 = hex-upper(nonce12[8:12])
             H  = the claims-commitment digest (commit2 law: custom-IV0
                  sha256 over 00*40 || nonce12 || sha0hex-upper || claims)
             C40= 40 raw bytes (cert SHA-1 hex on device; 40 NULs on the
                  emulator/default path)
             E64= hex-upper(sha256(b""))
           nonce12 on the default (no-keystore) path = the device constant
           d666bf3444ddccca7eada76a.
  state convention: measured cell order = transposed standard AES state;
  ShiftRows as measured: out[4r+c] = in[4((r+c)%4)+c]; MixColumns standard.

    python spn_law2.py   -> verifies both known mints byte-exact
"""
import hashlib
import hmac
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
sys.path.insert(0, WORK)
sys.path.insert(0, HERE)

DK37 = bytes.fromhex("2a4cc07960d647623cc386dcefafbf25"
                     "b669914d32cc8585a1ed7f920ef591eb")
SEED = bytes.fromhex("f110fb41676dba311f38c652c8f951ec"
                     "3db456c07b9166a509bef66cd870654b")
NONCE12_DEFAULT = bytes.fromhex("d666bf3444ddccca7eada76a")
CERT40_DEFAULT = b"\x00" * 40          # no keystore/cert on the default path

# ------------------------------------------------------------- AES core
AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
AES_INV = bytes(AES_SBOX.index(i) for i in range(256))


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xFF) ^ (0x1B if hi else 0)
        b >>= 1
    return p


_MCM = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
_IMC = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))


def mix_columns(b):
    out = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= gmul(col[j], _MCM[i][j])
            out[4 * q + i] = v
    return bytes(out)


def unmix_columns(b):
    out = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= gmul(col[j], _IMC[i][j])
            out[4 * q + i] = v
    return bytes(out)


def shift_rows(b):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r + c) % 4) + c]
    return bytes(out)


def unshift_rows(b):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * ((r + c) % 4) + c] = b[4 * r + c]
    return bytes(out)


def rot(t, n):
    n %= 4
    return t[n:] + t[:n]


def key_schedule(seed):
    """standard AES-256 expansion -> [K0..K14] (15 x 16 B)."""
    W = [list(seed[4 * i:4 * i + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        if i % 8 == 0:
            t = rot(W[i - 1], 1)
            t = [AES_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = ((rcon << 1) ^ 0x1B) & 0xFF if rcon & 0x80 else rcon << 1
        elif i % 8 == 4:
            t = [AES_SBOX[b] for b in W[i - 1]]
        else:
            t = W[i - 1]
        W.append([W[i - 8][j] ^ t[j] for j in range(4)])
    return [bytes(b for w in W[4 * r:4 * r + 4] for b in w)
            for r in range(15)]


KEYS = key_schedule(SEED)


def aes_block(P):
    x = bytes(a ^ b for a, b in zip(P, KEYS[0]))
    x = bytes(AES_SBOX[v] for v in x)
    for r in range(1, 14):
        x = mix_columns(shift_rows(x))
        x = bytes(a ^ b for a, b in zip(x, KEYS[r]))
        x = bytes(AES_SBOX[v] for v in x)
    return bytes(a ^ b for a, b in zip(shift_rows(x), KEYS[14]))


def aes_block_inv(C):
    y = unshift_rows(bytes(a ^ b for a, b in zip(C, KEYS[14])))
    for r in range(13, 0, -1):
        y = unshift_rows(unmix_columns(bytes(
            a ^ b for a, b in zip(bytes(AES_INV[v] for v in y), KEYS[r]))))
    return bytes(a ^ b for a, b in zip(bytes(AES_INV[v] for v in y), KEYS[0]))


def cbc_encrypt(iv, pt):
    out, prev = b"", iv
    for k in range(0, len(pt), 16):
        blk = bytes(a ^ b for a, b in zip(pt[k:k + 16], prev))
        prev = aes_block(blk)
        out += prev
    return out


def cbc_decrypt(iv, ct):
    out, prev = b"", iv
    for k in range(0, len(ct), 16):
        blk = ct[k:k + 16]
        out += bytes(a ^ b for a, b in zip(aes_block_inv(blk), prev))
        prev = blk
    return out


# ------------------------------------------------- header (from spn_law)
_M = (1 << 31) - 1
_A = 16807
_Q = _M // _A
_R = _M % _A


class BionicRand:
    def __init__(self, seed):
        r = self.r = [0] * 31
        s = seed & 0xFFFFFFFF or 1
        w = s if s < 2 ** 31 else s - 2 ** 32
        r[0] = w
        prev = w
        for i in range(1, 31):
            if prev >= 0:
                hi, lo = divmod(prev, _Q)
            else:
                hi = -((-prev) // _Q)
                lo = prev - hi * _Q
            word = _A * lo - _R * hi
            if word < 0:
                word += _M
            prev = word
            r[i] = word
        self.f, self.b = 3, 0
        for _ in range(310):
            self.next()

    def next(self):
        v = (self.r[self.f] + self.r[self.b]) & 0xFFFFFFFF
        self.r[self.f] = v if v < 2 ** 31 else v - 2 ** 32
        o = v >> 1
        self.f = (self.f + 1) % 31
        self.b = (self.b + 1) % 31
        return o


def make_header(unix_sec):
    R = BionicRand(unix_sec)
    d = [R.next() for _ in range(8)]
    w = [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return b"".join(v.to_bytes(4, "big") for v in w)


# ------------------------------------------ claims (from adj7_signer)
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
ADJ_SIGNING_ID = "1300000"
CLIENT_SDK = "flutter5.5.0@android5.5.0"


def build_claims(kind, params, client_sdk=None, include_block2=False):
    m = dict(params)
    if include_block2:
        m.setdefault("activity_kind", kind)
        m.setdefault("client_sdk", client_sdk or CLIENT_SDK)
    split = CLAIM_POOL.index("session_count")
    profile, tail, block2 = CLAIM_POOL[:split], CLAIM_POOL[split:-2], \
        CLAIM_POOL[-2:]
    parts = [str(m[k]) for k in profile if m.get(k) not in (None, "")]
    parts.append(ADJ_SIGNING_ID)
    parts += [str(m[k]) for k in tail if m.get(k) not in (None, "")]
    parts += [str(m[k]) for k in block2 if m.get(k) not in (None, "")]
    return "".join(parts).encode("latin1")


# ------------------------------------------ commitment digest (commit2)
IV0 = bytes.fromhex("16ba6d0211a298c282187e464c148c22"
                    "3a5cbc1506519f1497b9e37008ec3bec")
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def commitment_digest(claims, nonce12=NONCE12_DEFAULT, iv0=IV0):
    """H = custom-IV0 sha256 over 00*40 || nonce12 || sha0hex-upper || claims."""
    msg = (b"\x00" * 40 + nonce12 +
           hashlib.sha256(b"").hexdigest().upper().encode() + claims)
    padded = (msg + b"\x80" + b"\x00" * ((55 - len(msg) % 64) % 64) +
              struct.pack(">Q", len(msg) * 8))
    state = list(struct.unpack(">8I", iv0))
    for i in range(0, len(padded), 64):
        w = list(struct.unpack(">16I", padded[i:i + 64]))
        for j in range(16, 64):
            s0 = _rotr(w[j - 15], 7) ^ _rotr(w[j - 15], 18) ^ (w[j - 15] >> 3)
            s1 = _rotr(w[j - 2], 17) ^ _rotr(w[j - 2], 19) ^ (w[j - 2] >> 10)
            w.append((w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, h = state
        for j in range(64):
            S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            t1 = (h + S1 + ch + _K[j] + w[j]) & 0xFFFFFFFF
            S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & 0xFFFFFFFF
            h, g, f, e = g, f, e, (d + t1) & 0xFFFFFFFF
            d, c, b, a = c, b, a, (t1 + t2) & 0xFFFFFFFF
        state = [(x + y) & 0xFFFFFFFF for x, y in
                 zip(state, (a, b, c, d, e, f, g, h))]
    return b"".join(x.to_bytes(4, "big") for x in state)


# ----------------------------------------------------------- record law
def build_record(claims, nonce12=NONCE12_DEFAULT, cert40=CERT40_DEFAULT):
    a = str(struct.unpack("<Q", nonce12[:8])[0]).rjust(20)
    d = nonce12[8:12].hex().upper()
    H = commitment_digest(claims, nonce12).hex().upper()
    e = hashlib.sha256(b"").hexdigest().upper()
    js = (b'{ "a":  ' + a.encode() + b' ,"b": "' + H.encode() +
          b'","c": "' + cert40 + b'","d": "' + d.encode() +
          b'","e": "' + e.encode() + b'" }')
    return js + b"\x00" + b"\x10" * (256 - len(js) - 1)


def body_from(params, kind, unix_sec, nonce12=NONCE12_DEFAULT,
              cert40=CERT40_DEFAULT, include_block2=False, client_sdk=None):
    header = make_header(unix_sec)
    claims = build_claims(kind, params, client_sdk=client_sdk,
                          include_block2=include_block2)
    record = build_record(claims, nonce12, cert40)
    return cbc_encrypt(header, record)


def sign_blob(params, kind, unix_sec, nonce12=NONCE12_DEFAULT,
              cert40=CERT40_DEFAULT, include_block2=False, client_sdk=None):
    header = make_header(unix_sec)
    body = body_from(params, kind, unix_sec, nonce12, cert40,
                     include_block2, client_sdk)
    tag = hmac.new(DK37, body, hashlib.sha256).digest()
    return header + body + tag


def main():
    blob1 = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex"))
                          .read().strip())
    blob2 = bytes.fromhex(json.load(open(os.path.join(
        WORK, "adj7s4_out7.json")))["out_hex"])
    bodies = {b["sid"]: b for b in json.load(
        open(os.path.join(WORK, "adj7b_bodies.json")))}

    print("=== spn_law2: zero-unicorn closed form ===")
    for sid, blob, sec in (("0015", blob1, 1771238644),
                           ("0001", blob2, 1789382946)):
        params = dict(bodies[sid]["body_params_dict"])
        hdr = make_header(sec)
        body = body_from(params, "session", sec)
        want = blob[16:272]
        # per-block diff report
        diffs = [k for k in range(16)
                 if body[16 * k:16 * k + 16] != want[16 * k:16 * k + 16]]
        print("mint %s: header=%s body=%s (diff blocks: %s)"
              % (sid, hdr == blob[:16], body == want,
                 diffs if diffs else "none"))
        # round-trip: decrypt the genuine body and show the record
        rec = cbc_decrypt(blob[:16], want)
        print("  genuine record: %s"
              % "".join(chr(b) if 32 <= b < 127 else "." for b in rec[:64]))
    print("done")


if __name__ == "__main__":
    main()
