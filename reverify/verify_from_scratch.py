"""FROM-SCRATCH adj7 signature verifier -- fully independent implementation.

Nothing is imported from adj7_pure.py.  Every component is re-implemented
here from the raw spec: bionic rand() header, sha256 with custom IV,
AES-256 with the measured ShiftRows law (no final SubBytes), HMAC tag,
claims pool ordering, record format.

Verification chain per signed request (each step independent of the next):
  1. tag    : HMAC-SHA256(DK37, blob[16:272]) == blob[272:304]
  2. invert : law-cipher INVERSE decrypt of blob[16:272] -> 256-B record
              (valid JSON + 0x00/0x10 padding proves cipher+key schedule)
  3. nonce  : recovered from record a/d slots
  4. header : make_header(second) == blob[:16]  (second brute-forced
              around created_at/sent_at in both tz interpretations)
  5. H      : custom-IV sha256 over prefix || nonce || sha0hex || claims,
              prefix = cert SHA-1 ASCII (record's c) -- AND 00*40 variant
  6. remint : full blob rebuilt from wire fields + recovered nonce/second
              -> byte-exact vs the genuine blob
"""
import calendar
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import urllib.parse
from datetime import datetime, timedelta

BASE = os.path.dirname(os.path.abspath(__file__))
CAPS = os.path.join(BASE, "captures")

# ------------------------------------------------------------------
# recorded constants (from the 3.6x libsigner generation -- to be
# re-proven by successful inversion; a wrong constant yields garbage)
# ------------------------------------------------------------------
SEED = bytes.fromhex(
    "f110fb41676dba311f38c652c8f951ec"
    "3db456c07b9166a509bef66cd870654b")
DK37 = bytes.fromhex(
    "2a4cc07960d647623cc386dcefafbf25"
    "b669914d32cc8585a1ed7f920ef591eb")
IV0 = (0x16ba6d02, 0x11a298c2, 0x82187e46, 0x4c148c22,
       0x3a5cbc15, 0x06519f14, 0x97b9e370, 0x08ec3bec)

# claim pool: 97 keys, alphabetical core + activity_kind/client_sdk tail.
# NOTE: borrowed from the binscan law -- independently re-proven whenever
# an H match lands below (any pool error of order or membership breaks it).
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

SHA0_HEX = hashlib.sha256(b"").hexdigest().upper()

# ==================================================================
# SHA-256 with custom IV (compression implemented from scratch)
# ==================================================================
_PR64 = []
_n = 2
while len(_PR64) < 64:
    if all(_n % p for p in _PR64 if p * p <= _n):
        _PR64.append(_n)
    _n += 1
_K = []
for p in _PR64:
    # first 32 bits of the fractional part of the cube root of p
    t = p << 96
    lo, hi = 0, 16 << 32
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** 3 <= t:
            lo = mid
        else:
            hi = mid - 1
    _K.append(lo & 0xFFFFFFFF)  # drop the integer-part bit above 2^32
assert len(_K) == 64 and _K[0] == 0x428a2f98 and _K[63] == 0xc67178f2
_K = tuple(_K)

_M32 = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _M32


def _sha256_compress(state, blk16):
    w = list(blk16)
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
        s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _M32)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ ((~e & _M32) & g)
        t1 = (h + S1 + ch + _K[i] + w[i]) & _M32
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & _M32
        h, g, f, e = g, f, e, (d + t1) & _M32
        d, c, b, a = c, b, a, (t1 + t2) & _M32
    return [(x + s) & _M32 for x, s in zip((a, b, c, d, e, f, g, h), state)]


def sha256_custom_iv(msg, iv=IV0):
    pad = msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64)
    pad += struct.pack(">Q", len(msg) * 8)
    st = list(iv)
    for i in range(0, len(pad), 64):
        st = _sha256_compress(st, struct.unpack(">16I", pad[i:i + 64]))
    return struct.pack(">8I", *st)


# ==================================================================
# AES-256 with the measured law: ShiftRows M[r][c]=M[(r+c)%4][c],
# NO final SubBytes (out = SR(s13) ^ K14), textbook key schedule
# ==================================================================
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


def _affine(v):
    r = v
    for s in (1, 2, 3, 4):
        r ^= ((v << s) | (v >> (8 - s))) & 0xFF
    return r ^ 0x63


SBOX = bytes(_affine(0) if v == 0 else _affine(
    next(q for q in range(1, 256) if _gmul(v, q) == 1)) for v in range(256))
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
INV_SBOX = bytes(INV_SBOX)
assert SBOX[0] == 0x63 and SBOX[1] == 0x7c


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
    return [bytes(b for w in W[4 * r:4 * r + 4] for b in w)
            for r in range(15)]


RK = key_schedule(SEED)

MCM = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
MCMI = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))


def _mc(b, mat):
    out = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= _gmul(col[j], mat[i][j])
            out[4 * q + i] = v
    return bytes(out)


def sr_law(b):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r + c) % 4) + c]
    return bytes(out)


def sr_law_inv(b):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * ((r + c) % 4) + c] = b[4 * r + c]
    return bytes(out)


def spn_forward(P):
    """law encryption of one 16-B chunk"""
    x = bytes(a ^ b for a, b in zip(P, RK[0]))
    x = bytes(SBOX[v] for v in x)
    for r in range(13):
        x = sr_law(x)
        x = _mc(x, MCM)
        x = bytes(a ^ b for a, b in zip(x, RK[1 + r]))
        x = bytes(SBOX[v] for v in x)
    x = sr_law(x)
    return bytes(a ^ b for a, b in zip(x, RK[14]))


def spn_inverse(C):
    """exact inverse of spn_forward"""
    x = bytes(a ^ b for a, b in zip(C, RK[14]))
    x = sr_law_inv(x)                      # s13
    for r in range(12, -1, -1):
        x = bytes(INV_SBOX[v] for v in x)
        x = bytes(a ^ b for a, b in zip(x, RK[1 + r]))
        x = _mc(x, MCMI)
        x = sr_law_inv(x)
    x = bytes(INV_SBOX[v] for v in x)
    x = bytes(a ^ b for a, b in zip(x, RK[0]))
    return x


def cbc_decrypt(body, iv):
    out, prev = b"", iv
    for k in range(0, len(body), 16):
        blk = body[k:k + 16]
        out += bytes(a ^ b for a, b in zip(spn_inverse(blk), prev))
        prev = blk
    return out


def cbc_encrypt(record, iv):
    out, prev = b"", iv
    for k in range(0, len(record), 16):
        prev = spn_forward(bytes(a ^ b for a, b in zip(record[k:k + 16],
                                                       prev)))
        out += prev
    return out


# ==================================================================
# bionic rand() header: TYPE_3 additive feedback, 310-draw warm-up
# ==================================================================
_M31 = 2147483647
_A31 = 16807


def _schrage(prev):
    hi, lo = divmod(prev, _M31 // _A31)
    y = lo * _A31 - hi * (_M31 % _A31)
    return y + _M31 if y < 0 else y


def make_header(unix_sec):
    s = int(unix_sec) & 0xFFFFFFFF or 1
    w = s if s < 2 ** 31 else s - 2 ** 32
    r = [w]
    for _ in range(30):
        r.append(_schrage(r[-1]))
    f, b = 3, 0

    def nxt():
        nonlocal f, b
        v = (r[f] + r[b]) & 0xFFFFFFFF
        r[f] = v if v < _M31 else v - 2 ** 32
        f = (f + 1) % 31
        b = (b + 1) % 31
        return v >> 1

    for _ in range(310):
        nxt()
    d = [nxt() for _ in range(8)]
    return b"".join(((d[2 * i] ^ d[2 * i + 1]) & 0xFFFFFFFF).to_bytes(
        4, "big") for i in range(4))


# ==================================================================
# claims (pool order, block2 append)
# ==================================================================
def build_claims(fields, kind, client_sdk):
    m = dict(fields)
    m.setdefault("activity_kind", kind)
    m.setdefault("client_sdk", client_sdk or "")
    split = CLAIM_POOL.index("seq")
    profile, tail, block2 = (CLAIM_POOL[:split], CLAIM_POOL[split:-2],
                             CLAIM_POOL[-2:])
    parts = [str(m[k]) for k in profile if m.get(k) not in (None, "")]
    parts.append("1300000")
    parts += [str(m[k]) for k in tail if m.get(k) not in (None, "")]
    parts += [str(m[k]) for k in block2 if m.get(k) not in (None, "")]
    return "".join(parts).encode("latin1")


# ==================================================================
# capture parsing
# ==================================================================
REQ_RE = re.compile(
    r'\{ "a":  +(?P<A>\d+) ,"b": "(?P<H>[0-9A-F]{64})","c": "(?P<C>[^"]*)"'
    r',"d": "(?P<D>[0-9A-F]{8})","e": "(?P<E>[0-9A-F]{64})" \}')


def parse_request(data):
    i = data.find(b"\r\n\r\n")
    head, body = (data[:i], data[i + 4:]) if i >= 0 else (data, b"")
    lines = head.split(b"\r\n")
    reqline = lines[0].decode("latin1")
    m = re.match(r"(\S+)\s+(\S+)\s+HTTP/[\d.]+", reqline)
    method, path = m.group(1), m.group(2)
    headers = {}
    for ln in lines[1:]:
        j = ln.find(b":")
        if j > 0:
            headers[ln[:j].decode("latin1").strip().lower()] = \
                ln[j + 1:].decode("latin1").strip()
    return method, path, headers, body


def parse_ts(s):
    """'2026-10-06T11:54:14.123Z+0530' -> (utc_epoch, naive_epoch)"""
    m = re.match(r"(.*?)Z([+-]\d{4})?$", s)
    if not m:
        return None
    naive = datetime.strptime(m.group(1).split(".")[0], "%Y-%m-%dT%H:%M:%S")
    tz = m.group(2) or "+0000"
    sgn = 1 if tz[0] == "+" else -1
    delta = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sgn
    return (calendar.timegm((naive - delta).timetuple()),
            calendar.timegm(naive.timetuple()))


def request_fields(method, path, body_raw):
    fields = {}
    if method == "POST":
        fields = dict(urllib.parse.parse_qsl(body_raw.decode("latin1"),
                                             keep_blank_values=True))
    q = path.split("?", 1)
    if len(q) == 2:
        fields.update(dict(urllib.parse.parse_qsl(q[1],
                                                  keep_blank_values=True)))
    return fields


def ts_candidates(fields):
    cands = set()
    for k in ("created_at", "sent_at", "click_time", "click_time_server",
              "installed_at"):
        v = fields.get(k)
        if not v:
            continue
        p = parse_ts(v)
        if p is None:
            continue
        for base in p:
            for d in (-2, -1, 0, 1, 2):
                cands.add(base + d)
    return sorted(cands)


def check_request(cap, sid, method, path, headers, body_raw, extra_secs=()):
    endpoint = path.split("?")[0].rsplit("/", 1)[-1]
    # LAW (verified by H match on all captures): the claims'
    # activity_kind for the /sdk_click endpoint is "click" (the wire
    # endpoint name is NOT the activity kind); others use the endpoint.
    kind = "click" if endpoint == "sdk_click" else endpoint
    auth = headers.get("authorization", "")
    msig = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
    if not msig:
        return None
    ap = dict(re.findall(r'(\w+)="([^"]*)"', auth))
    blob = bytes.fromhex(msig.group(1))
    fields = request_fields(method, path, body_raw)
    res = {"capture": cap, "sid": sid, "kind": kind, "method": method,
           "auth": {k: v for k, v in ap.items() if k != "signature"},
           "n_fields": len(fields), "client_sdk_hdr":
               headers.get("client-sdk", "")}
    oks = []

    # 1. tag
    oks.append(("tag", hmac.new(DK37, blob[16:272],
                                hashlib.sha256).digest() == blob[272:304]))

    # 2. invert body -> record
    rec = cbc_decrypt(blob[16:272], blob[:16])
    mrec = REQ_RE.search(rec.decode("latin1", "replace"))
    oks.append(("invert+record", mrec is not None))
    if not mrec:
        res["checks"] = dict(oks)
        return res
    pad = rec[mrec.end():]
    oks.append(("padding-shape", len(pad) + mrec.end() == 256
                and set(pad) <= {0x00, 0x10}))
    A, H, C, D8, E = (mrec.group("A"), mrec.group("H"), mrec.group("C"),
                      mrec.group("D"), mrec.group("E"))
    res["record"] = {"c": C, "H": H, "d": D8, "a": A, "pad_len": len(pad)}
    oks.append(("e==sha0", E == SHA0_HEX))
    nonce12 = int(A).to_bytes(8, "little") + bytes.fromhex(D8)
    res["nonce12"] = nonce12.hex()

    # 3. header law (second brute; fall back to capture-wide window)
    sec = next((c for c in list(ts_candidates(fields)) + list(extra_secs)
                if make_header(c) == blob[:16]), None)
    oks.append(("header(second=%s)" % sec, sec is not None))

    # 4. H law with the two prefixes
    claims = build_claims(fields, kind, headers.get("client-sdk", ""))
    res["claims_len"] = len(claims)
    H_c = sha256_custom_iv(C.encode() + nonce12 + SHA0_HEX.encode()
                           + claims).hex().upper()
    H_00 = sha256_custom_iv(b"\x00" * 40 + nonce12 + SHA0_HEX.encode()
                            + claims).hex().upper()
    oks.append(("H(cert-prefix)", H_c == H))
    oks.append(("H(00-prefix)", H_00 == H))
    res["h_matches"] = "cert" if H_c == H else ("00" if H_00 == H
                                                else "NEITHER")

    # 5. full re-mint byte-exact (record rebuilt from MY law + wire fields)
    if sec is not None and (H_c == H or H_00 == H):
        H_use = H_c if H_c == H else H_00
        A2 = str(int.from_bytes(nonce12[0:8], "little")).rjust(20)
        j = ('{ "a":  ' + A2 + ' ,"b": "' + H_use + '","c": "' + C
             + '","d": "' + D8 + '","e": "' + SHA0_HEX + '" }\x00')
        rec2 = j.encode() + b"\x10" * (256 - len(j))
        oks.append(("record-rebuild", rec2 == rec))
        body2 = cbc_encrypt(rec2, blob[:16])
        blob2 = blob[:16] + body2 \
            + hmac.new(DK37, body2, hashlib.sha256).digest()
        oks.append(("remint-byte-exact", blob2 == blob))
    res["checks"] = dict(oks)
    return res


def main():
    names = sys.argv[1:] or sorted(os.listdir(CAPS))
    all_rows = []
    for cap in names:
        d = os.path.join(CAPS, cap, "raw")
        sids = sorted({f.split("_")[0] for f in os.listdir(d)
                       if f.endswith("_c.txt")}, key=int)
        # capture-wide time window (fallback for attribution GETs)
        win = []
        for sid in sids:
            meth, pth, hdrs, body = parse_request(
                open(os.path.join(d, sid + "_c.txt"), "rb").read())
            fs = request_fields(meth, pth, body)
            for k in ("created_at", "sent_at"):
                if fs.get(k):
                    p = parse_ts(fs[k])
                    if p:
                        win += list(p)
        extra = []
        if win:
            for base in (min(win), max(win)):
                extra += [base + dd for dd in range(-10, 11)]
        for sid in sids:
            data = open(os.path.join(d, sid + "_c.txt"), "rb").read()
            meth, pth, hdrs, body = parse_request(data)
            if ".adjust." not in hdrs.get("host", "").lower():
                continue
            if "signature=" not in hdrs.get("authorization", ""):
                continue
            r = check_request(cap, sid, meth, pth, hdrs, body, extra)
            if r:
                all_rows.append(r)
    npass = nfail = 0
    for r in all_rows:
        print("%-14s sid%-4s %-11s %2d flds  c=%s  nonce=%s" % (
            r["capture"], r["sid"], r["kind"], r["n_fields"],
            r.get("record", {}).get("c", "-")[:40],
            r.get("nonce12", "-")))
        for k, v in r["checks"].items():
            print("    %-28s %s" % (k, "OK" if v else "** FAIL **"))
            npass += 1 if v else 0
            nfail += 0 if v else 1
        print()
    print("TOTAL: %d OK, %d FAIL across %d signed requests"
          % (npass, nfail, len(all_rows)))
    with open(os.path.join(BASE, "findings", "verify_report.json"),
              "w") as f:
        json.dump(all_rows, f, indent=1, default=str)


if __name__ == "__main__":
    main()
