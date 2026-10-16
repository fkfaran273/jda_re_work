# -*- coding: utf-8 -*-
"""adj7_ios_pure.py -- pure-Python signer for the iOS adj7 variant
(native_version 3.61.0, headers_id "7"), cracked from the
nirioiosauto_08Sep_ios_CT.saz capture (com.fdjservices.nirio, iOS 16.4.6).

The iOS law is the ANDROID law (adj7/adj7_pure.py) with ONE crypto delta:

    header  : raw MINSTD instead of bionic rand()
                  x0 = seed (= signing unix second)
                  x  = 16807 * x mod 2147483647        (8 draws)
                  w[i] = d[2i] ^ d[2i+1];  header = w[0..3] big-endian
              (Android uses the 31-word bionic LCG + 310-draw warm-up;
               iOS uses the raw Lehmer generator with NO warm-up.)

Everything else is shared verbatim with Android:

    blob(304) = header(16) || body(256) || tag(32)
    body      = CBC-AES-256(record, IV=header, key=SEED) over the measured
                ShiftRows SPN (no final SubBytes)
    record    = '{ "a":  <A> ,"b": "<H>","c": "<cert40>","d": "<D8>",
                 "e": "<sha256('') hex-upper>" }\x00' + 0x10*16
                A = str(u64le(nonce12[0:8])) rjust 20; D8 = nonce12[8:12] hex
    cert40    = ASCII "0" * 40 on the iOS no-cert path (Android: NUL bytes)
    H         = sha256 with custom IV0 over  cert40 || nonce12 || sha0hex
                || claims
    claims    = 98-key pool order, values bare, "1300000" pinned before seq,
                block2 (activity_kind, client_sdk) appended last
                -- iOS activity_kind values: session | click | event |
                attribution | third_party_sharing
    tag       = HMAC-SHA256(DK37, blob[16:272])

Auth header:  Signature signature="<608 hex UPPER>",
              adj_signing_id="1300000", algorithm="adj7",
              headers_id="7", native_version="3.61.0"

    python adj7_ios_pure.py --selftest
"""
import hashlib
import hmac
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from adj7_pure import (CLAIM_POOL, DK37, IV0, SHA0_HEX, SEED,  # noqa: E402
                       _RK, build_claims, cbc_encrypt, commitment_digest)

M31 = 2147483647
A31 = 16807

CERT40_IOS = b"0" * 40          # iOS no-cert path: ASCII zeros (not NULs)
ADJ_SIGNING_ID = "1300000"
ALGORITHM = "adj7"
HEADERS_ID = "7"
NATIVE_VERSION = "3.61.0"


# ======================================================================
# PART 1 -- header: raw MINSTD, 8 draws, pair-XOR, big-endian
# ======================================================================
class MinstdRand:
    """Lehmer generator x = 16807*x mod 2147483647, seeded with the second."""

    def __init__(self, seed):
        self.x = int(seed) % M31 or 1

    def next(self):
        self.x = (A31 * self.x) % M31
        return self.x


def make_header(unix_sec):
    R = MinstdRand(int(unix_sec))
    d = [R.next() for _ in range(8)]
    w = [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return b"".join(v.to_bytes(4, "big") for v in w)


# ======================================================================
# PART 2 -- record + signature (record/cert40 carry the iOS default)
# ======================================================================
def build_record_ios(H, nonce12, cert40=CERT40_IOS):
    A = str(int.from_bytes(nonce12[0:8], "little")).rjust(20)
    d8 = nonce12[8:12].hex().upper()
    j = (b'{ "a":  ' + A.encode() + b' ,"b": "' + H.hex().upper().encode()
         + b'","c": "' + cert40 + b'","d": "' + d8.encode()
         + b'","e": "' + SHA0_HEX.encode() + b'" }\x00')
    return j + b"\x10" * (256 - len(j))


def sign(second, nonce12, claims, cert40=CERT40_IOS, keys=_RK):
    header = make_header(int(second))
    H = commitment_digest(claims, nonce12, cert40)
    record = build_record_ios(H, nonce12, cert40)
    body = cbc_encrypt(record, header, keys)
    return header + body + hmac.new(DK37, body, hashlib.sha256).digest()


def sign_request(fields, kind, second=None, nonce12=None, client_sdk=None,
                 cert40=CERT40_IOS):
    """Sign one request -> (auth_header_value, blob).

    fields     the wire map (str -> str) -- the form body or query params
    kind       activity_kind: session | click | event | attribution |
               third_party_sharing
    second     signing unix second (None -> now)
    nonce12    12-B nonce; None -> urandom (device behaviour)
    client_sdk the Client-Sdk header value, e.g. 'react-native5.4.4@ios5.4.6'
    """
    import time as _time
    if second is None:
        second = int(_time.time())
    if nonce12 is None:
        nonce12 = os.urandom(12)
    claims = build_claims(kind, fields, client_sdk=client_sdk or "",
                          include_block2=True)
    blob = sign(second, nonce12, claims, cert40)
    auth = ('Signature signature="%s",adj_signing_id="%s",algorithm="%s",'
            'headers_id="%s",native_version="%s"'
            % (blob.hex().upper(), ADJ_SIGNING_ID, ALGORITHM, HEADERS_ID,
               NATIVE_VERSION))
    return auth, blob


# ======================================================================
# PART 3 -- selftest against the six FROZEN capture vectors
# (inlined -- the selftest must never depend on a side file that can be
#  regenerated; sigs are the genuine capture signatures)
# ======================================================================
RECORD_RE = (rb'\{ "a":  ([ 0-9]{20}) ,"b": "([0-9A-Fa-f]{64})","c": "'
             rb'(.{40})","d": "([0-9A-Fa-f]{8})","e": "([0-9A-Fa-f]{64})" \}')
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
INVBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INVBOX[_v] = _i
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]
ICM = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return p


def _key_schedule(key):
    W = [list(key[i * 4:i * 4 + 4]) for i in range(8)]
    for i in range(8, 60):
        t = list(W[i - 1])
        if i % 8 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i // 8 - 1]
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        W.append([W[i - 8][j] ^ t[j] for j in range(4)])
    return [bytes(b for w in W[4 * r:4 * r + 4] for b in w) for r in range(15)]


def _sr_inverse(b):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r - c) % 4) + c]
    return bytes(out)


def _mix(b, mat):
    out = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= _gmul(col[j], mat[i][j])
            out[4 * q + i] = v
    return bytes(out)


def cbc_decrypt(body, header, keys=None):
    """Independent inverse SPN -- proves the forward law inverts cleanly."""
    keys = keys or _key_schedule(SEED)

    def spn_inv(C):
        y = _sr_inverse(bytes(a ^ b for a, b in zip(C, keys[14])))
        for r in range(13, 0, -1):
            c = bytes(INVBOX[v] for v in y)
            b = bytes(a ^ b for a, b in zip(c, keys[r]))
            a = _mix(b, ICM)
            y = _sr_inverse(a)
        p = bytes(INVBOX[v] for v in y)
        return bytes(a ^ b for a, b in zip(p, keys[0]))

    out, prev = b"", header
    for k in range(0, len(body), 16):
        blk = body[k:k + 16]
        out += bytes(a ^ b for a, b in zip(spn_inv(blk), prev))
        prev = blk
    return out


def _frozen_vectors():
    """The 6 capture vectors, inlined (from frozen_vectors.json 2026-10-07,
    verified byte-exact + freeze script's BRUTE_SECONDS seconds).  Params
    stay in frozen_vectors.json; the frozen file is regenerated ONLY by
    freeze_vectors.py and re-checked against these sigs."""
    path = os.path.join(HERE, "frozen_vectors.json")
    with open(path, encoding="utf-8") as f:
        vectors = json.load(f)
    frozen = [
        ("32", 1788846069, "8e1f0ea725e80fa6ec9a24af",
         "0AE9BB1F6DB534507518AE4377BEA206DD9B31A88A08797BAAED1A1BD4D96FFFDCC4F6FA66423BDF0C9B86BBCA1511065FF"),
        ("33", 1788846069, "0fab290e7924e9c1571f3665",
         "0AE9BB1F6DB534507518AE4377BEA206C456059306E3C8AE4491A2B83F688E1D740AD59A75DE63CD19505D568790470A197"),
        ("36", 1788846070, "dc3491e4e4fc460f8457f07f",
         "2592BCA775B67D0015455F39004BED3C23CC6B69CD5507D58E0D48E14D96C8F6092ECE5DA7C89AD294C00587005769AE2D1"),
        ("37", 1788846071, "47b56928e2af8e65ccf056a8",
         "54BCB2AF50D3B2562571ECD131147853EBF798FA899AE3EFAEDDAFD2EE6D4F2F053F76B94303101D184170691DB77FD371F"),
        ("38", 1788846073, "0e9f9329a1cb244757aba1ad",
         "770FA07F03FD910F75FCD7261353B7A00A32FA993166ABD067D4746A2847AAC992A8E535D8169DE2BE34F6CD46017CCAB5E"),
        ("39", 1788846076, "d6f5b597355eefc28fe6e520",
         "00F38C201143977B2A44AD777D924035C4F9AFD7A5C030218092D120E60606C6750CBD033625EFE5D74CE7C9AA458B394E0"),
    ]
    by_sid = {v["sid"]: v for v in vectors}
    for sid, sec, nonce, sighead in frozen:
        v = by_sid[sid]
        v["second"] = sec
        v["nonce12"] = nonce
        assert v["sig"].startswith(sighead), (
            f"frozen_vectors.json sid {sid} does not match the captured "
            f"signature -- regenerate with freeze_vectors.py and confirm")
    return vectors


def selftest():
    import re as _re
    vectors = _frozen_vectors()
    n_ok = 0
    for v in vectors:
        blob = sign(v["second"], bytes.fromhex(v["nonce12"]),
                    build_claims(v["kind"], v["params"],
                                 client_sdk=v["client_sdk"],
                                 include_block2=True))
        if blob.hex().upper() != v["sig"]:
            print(f"FAIL sid {v['sid']}: mint != capture")
            continue
        # independent re-verify: tag + decrypt + record + H
        header, body, tag = blob[:16], blob[16:272], blob[272:]
        assert hmac.compare_digest(
            hmac.new(DK37, body, hashlib.sha256).digest(), tag), "tag"
        rec = cbc_decrypt(body, header)
        m = _re.match(RECORD_RE, rec)
        assert m, "record"
        nonce12 = (int(m.group(1).decode().strip()).to_bytes(8, "little")
                   + bytes.fromhex(m.group(4).decode()))
        assert nonce12 == bytes.fromhex(v["nonce12"]), "nonce round-trip"
        H = commitment_digest(build_claims(v["kind"], v["params"],
                                           client_sdk=v["client_sdk"],
                                           include_block2=True),
                              nonce12, CERT40_IOS)
        assert H.hex().upper() == m.group(2).decode(), "H round-trip"
        n_ok += 1
        print(f"ok sid {v['sid']:>2s} {v['kind']:20s} sec={v['second']} "
              f"blob={blob.hex().upper()[:16]}.. BYTE-EXACT")
    # header law spot checks (distinct seconds from the capture)
    assert make_header(1788846069).hex() == "0ae9bb1f6db534507518ae4377bea206"
    assert make_header(1788846076).hex() == "00f38c201143977b2a44ad777d924035"
    print(f"\n{len(vectors)} mint vectors, {n_ok} byte-exact; "
          f"tag+decrypt+record+H re-verified on all; header law checked")
    if n_ok != len(vectors):
        raise SystemExit(1)
    print("SELFTEST OK")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        print(__doc__)
