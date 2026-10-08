# -*- coding: utf-8 -*-
"""probe_ios.py -- step 1 of the iOS adj7 crack.

Reuses the proven Android machinery (tag law, SEED decrypt, record parse)
verbatim against the 6 signed iOS requests from nirioiosauto_08Sep_ios_CT.saz.

No guesses here: everything in this file is the *Android* law applied to the
iOS blobs.  Whatever matches, matches; whatever doesn't tells us where iOS
diverges.
"""
import hashlib
import hmac
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from adj7_pure import (DK37, SEED, IV0, CLAIM_POOL, SHA0_HEX,  # noqa: E402
                       commitment_digest, build_record)

# ---- inverse SPN (independent reimpl, mirrors work/audit_hunt/audit_decrypt.py)
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


def xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = xtime(a)
        b >>= 1
    return p


def key_schedule(key):
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


RK = key_schedule(SEED)


def sr_forward(b):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r + c) % 4) + c]
    return bytes(out)


def sr_inverse(b):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r - c) % 4) + c]
    return bytes(out)


MCM = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
ICM = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))


def mix(b, mat):
    out = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= gmul(col[j], mat[i][j])
            out[4 * q + i] = v
    return bytes(out)


def spn_inv(C, keys):
    y = sr_inverse(bytes(a ^ b for a, b in zip(C, keys[14])))
    for r in range(13, 0, -1):
        c = bytes(INVBOX[v] for v in y)
        b = bytes(a ^ b for a, b in zip(c, keys[r]))
        a = mix(b, ICM)
        y = sr_inverse(a)
    p = bytes(INVBOX[v] for v in y)
    return bytes(a ^ b for a, b in zip(p, keys[0]))


def cbc_decrypt(body, header):
    out, prev = b"", header
    for k in range(0, len(body), 16):
        blk = body[k:k + 16]
        rec = spn_inv(blk, RK)
        out += bytes(a ^ b for a, b in zip(rec, prev))
        prev = blk
    return out


# ---- round-trip guard: our decrypt must invert the proven Android encrypt
def _roundtrip_guard():
    sys.path.insert(0, os.path.join(HERE, ".."))
    from adj7_pure import cbc_encrypt
    rec = bytes((i * 37 + 11) % 256 for i in range(256))
    hdr = bytes((i * 91 + 7) % 256 for i in range(16))
    ct = cbc_encrypt(rec, hdr)
    assert cbc_decrypt(ct, hdr) == rec, "decrypt/encrypt round-trip FAILED"
    print("[guard] inverse-SPN round-trip against adj7_pure: OK")


# ---- record parse (Android layout: '{ "a": ... ,"b": ... ,"c": ... ,"d": ... ,"e": ... }')
RECORD_RE = re.compile(
    rb'\{ "a":  (\d{20}) ,"b": "([0-9A-Fa-f]{64})","c": "(.{40})","d": "'
    rb'([0-9A-Fa-f]{8})","e": "([0-9A-Fa-f]{64})" \}')


def parse_record(rec):
    m = RECORD_RE.search(rec)
    if not m:
        return None
    a = m.group(1).decode()
    b = m.group(2).decode()
    c = m.group(3)
    d = m.group(4).decode()
    e = m.group(5).decode()
    nonce12 = int(a).to_bytes(8, "little") + bytes.fromhex(d)
    return {"a": a, "H": b, "cert40": c, "d8": d, "e": e, "nonce12": nonce12}


def main():
    _roundtrip_guard()
    jf = os.path.join(HERE, "nirio_08Sep", "nirioiosauto_08Sep_ios_CT_adjust.json")
    recs = json.load(open(jf, encoding="utf-8"))
    print(f"\n{len(recs)} iOS signed requests\n")
    for r in recs:
        auth = next((v for k, v in r["request_headers"]
                     if k.lower() == "authorization"), "")
        print(f"--- sid {r['sid']} {r['method']} {r['url']}")
        print(f"    Authorization ({len(auth)} chars): {auth[:120]}...")
        extra = re.sub(r'^\s*Signature\s*', '', auth.split('signature="')[0]).strip()
        if extra:
            print(f"    EXTRA auth params: {extra!r}")
        sig = re.search(r'signature="([^"]+)"', auth).group(1)
        blob = bytes.fromhex(sig)
        print(f"    blob {len(blob)} B  header={blob[:16].hex()}")
        # (1) tag law
        body, tag = blob[16:272], blob[272:304]
        want = hmac.new(DK37, body, hashlib.sha256).digest()
        print(f"    tag law (HMAC-DK37 over body): "
              f"{'MATCH' if hmac.compare_digest(want, tag) else 'MISS'}")
        # (2) decrypt
        rec = cbc_decrypt(body, blob[:16])
        printable = sum(32 <= c < 127 for c in rec)
        print(f"    decrypted 256B printable={printable}/256  "
              f"tail={rec[-16:].hex()}")
        p = parse_record(rec)
        if p:
            print(f"    a={p['a']}")
            print(f"    H={p['H']}")
            print(f"    c={p['cert40'].decode('latin1')!r}")
            print(f"    d={p['d8']}  e={p['e']}")
            print(f"    nonce12={p['nonce12'].hex()}")
            # (3) e == sha256('') hex upper?
            print(f"    e==sha0hex: {p['e'] == SHA0_HEX}")
        else:
            print(f"    RECORD PARSE FAILED; raw tail: {rec[-96:]!r}")
        print()


if __name__ == "__main__":
    main()
