# -*- coding: utf-8 -*-
"""probe2_claims.py -- test the Android claims law against the iOS records.

For each signed request: rebuild the claims string from the request's own
params (Android 98-key pool, pool order, values bare, "1300000" pinned before
seq, block2 last), then H = sha256_iv0(prefix || nonce12 || sha0hex || claims)
and compare with the H inside the decrypted record.

Variants probed per request:
  prefix   = ASCII "0"*40 (the iOS c-slot content)  |  NUL*40 (Android no-cert)
  block2   = none | activity_kind guesses | client_sdk from Client-Sdk header
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from adj7_pure import (CLAIM_POOL, SHA0_HEX,  # noqa: E402
                       commitment_digest, sha256_iv0)

RECORD_RE = re.compile(
    rb'\{ "a":  ([ 0-9]{20}) ,"b": "([0-9A-Fa-f]{64})","c": "(.{40})","d": "'
    rb'([0-9A-Fa-f]{8})","e": "([0-9A-Fa-f]{64})" \}')
CIPHER_RE = re.compile(r'signature="([^"]+)"')
TAIL_RE = re.compile(r',(\w+)="([^"]*)"')

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


def sr_inverse(b):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r - c) % 4) + c]
    return bytes(out)


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


def cbc_decrypt(body, header, RK):
    def spn_inv(C):
        y = sr_inverse(bytes(a ^ b for a, b in zip(C, RK[14])))
        for r in range(13, 0, -1):
            c = bytes(INVBOX[v] for v in y)
            b = bytes(a ^ b for a, b in zip(c, RK[r]))
            a = mix(b, ICM)
            y = sr_inverse(a)
        p = bytes(INVBOX[v] for v in y)
        return bytes(a ^ b for a, b in zip(p, RK[0]))

    out, prev = b"", header
    for k in range(0, len(body), 16):
        blk = body[k:k + 16]
        out += bytes(a ^ b for a, b in zip(spn_inv(blk), prev))
        prev = blk
    return out


def parse_record(rec):
    m = RECORD_RE.search(rec)
    if not m:
        return None
    a = m.group(1).decode().strip()
    nonce12 = int(a).to_bytes(8, "little") + bytes.fromhex(m.group(4).decode())
    return {"a": a, "H": m.group(2).decode(), "cert40": m.group(3),
            "nonce12": nonce12}


def build_claims_variants(m, client_sdk):
    """Yield (label, claims_bytes) candidates."""
    present = lambda k: k in m and m[k] not in (None, "")
    split = CLAIM_POOL.index("seq")
    profile, tail, block2 = CLAIM_POOL[:split], CLAIM_POOL[split:-2], CLAIM_POOL[-2:]

    def render(activity_kind=None, with_cs=False):
        parts = [str(m[k]) for k in profile if present(k)]
        parts.append("1300000")
        parts += [str(m[k]) for k in tail if present(k)]
        if activity_kind is not None:
            parts.append(activity_kind)
        if with_cs:
            parts.append(client_sdk)
        return "".join(parts).encode("latin1")

    out = [("pool", render())]
    for ak in ("session", "click", "third_party_sharing", "attribution",
               "event", None):
        label = "pool+block2(ak=%s,cs)" % ak
        out.append((label, render(activity_kind=ak, with_cs=True)))
    out.append(("pool+block2(ak=None,cs)", render(activity_kind=None,
                                                  with_cs=True)))
    return out


def main():
    SEED = bytes.fromhex(
        "f110fb41676dba311f38c652c8f951ec"
        "3db456c07b9166a509bef66cd870654b")
    RK = key_schedule(SEED)
    jf = os.path.join(HERE, "nirio_08Sep",
                      "nirioiosauto_08Sep_ios_CT_adjust.json")
    recs = json.load(open(jf, encoding="utf-8"))
    results = []
    for r in recs:
        auth = next((v for k, v in r["request_headers"]
                     if k.lower() == "authorization"), "")
        client_sdk = next((v for k, v in r["request_headers"]
                           if k.lower() == "client-sdk"), "")
        blob = bytes.fromhex(CIPHER_RE.search(auth).group(1))
        rec = cbc_decrypt(blob[16:272], blob[:16], RK)
        p = parse_record(rec)
        if not p:
            print(f"sid {r['sid']}: RECORD PARSE FAIL {rec[:60]!r}...")
            continue
        # param map: form body for POSTs, query string for GETs
        if isinstance(r["body"], dict):
            m = dict(r["body"])
        else:
            from urllib.parse import parse_qsl, urlsplit
            q = urlsplit(r["url"]).query
            m = dict(parse_qsl(q, keep_blank_values=True))
        nonce12 = p["nonce12"]
        Hwant = p["H"].encode()
        hit = None
        variants = build_claims_variants(m, client_sdk)
        for prefix_label, prefix in (("ascii0", b"0" * 40),
                                     ("nul", b"\x00" * 40)):
            for vlabel, claims in variants:
                H = commitment_digest(claims, nonce12, prefix)
                if H.hex().upper() == p["H"]:
                    hit = (prefix_label, vlabel, claims)
                    break
            if hit:
                break
        status = f"MATCH [{hit[0]}/{hit[1]}]" if hit else "NO MATCH"
        print(f"sid {r['sid']} {r['url'].split('?')[0].split('/')[-1]:20s} "
              f"nonce12={nonce12.hex()} H={p['H'][:16]}... -> {status}")
        if hit:
            print(f"    claims ({len(hit[2])} B): {hit[2][:200]!r}")
        else:
            print(f"    pool-filtered map: "
                  f"{[k for k in CLAIM_POOL if m.get(k) not in (None, '')]}")
            print(f"    map extras (not in pool): "
                  f"{sorted(set(m) - set(CLAIM_POOL))}")
        results.append((r["sid"], p, m, hit))
    n_ok = sum(1 for _, _, _, h in results if h)
    print(f"\n{len(results)} records parsed, {n_ok} claims MATCH")


if __name__ == "__main__":
    main()
