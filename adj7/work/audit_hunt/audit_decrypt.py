# -*- coding: utf-8 -*-
"""audit_decrypt.py -- INDEPENDENT decryption of genuine adj7 blobs.

Deliberately does NOT import adj7_pure.  Implements:
  - the textbook AES-256 key schedule over the recorded SEED,
  - the inverse of the measured SPN round (SR-law out[4r+c]=in[4((r+c)%4)+c],
    MixColumns, AddRoundKey, SubBytes; tail = SR then AK, no final SBOX),
  - CBC chaining with the blob's 16-B header as IV.

Then decrypts the four payrupi.chls signatures and prints the full 256-B
records (a/b/c/d/e), verifying the DK37 tag of each first.
"""
import hashlib
import hmac
import re
import sys

SEED = bytes.fromhex(
    "f110fb41676dba311f38c652c8f951ec"
    "3db456c07b9166a509bef66cd870654b")
DK37 = bytes.fromhex(
    "2a4cc07960d647623cc386dcefafbf25"
    "b669914d32cc8585a1ed7f920ef591eb")

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
for i, v in enumerate(SBOX):
    INVBOX[v] = i

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
    """Inverse of: x=P^K0; x=S(x); 13x[SR,MC,AK,SB]; SR; AK."""
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
        dec = spn_inv(blk, RK)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return out


def parse_record(rec):
    import urllib.parse
    s = rec.split(b"\x00")[0].decode("latin1")
    out = {}
    for key in ("a", "b", "c", "d", "e"):
        m = re.search(r'"%s": ?"?([^"]*?)"?[,}]' % key, s)
        out[key] = m.group(1) if m else None
    out["raw_prefix"] = s[:60]
    return out


def main():
    data = open(r"C:\Users\Apps\Downloads\payrupi.chls", "rb").read()
    sigs = []
    for m in re.finditer(rb"[0-9A-F]{608}", data):
        h = m.group(0).decode()
        if h not in [s[0] for s in sigs]:
            sigs.append((h, m.start()))
    kinds = ["session", "sdk_click", "attribution", "event"]
    recs = {}
    for i, (h, pos) in enumerate(sigs):
        blob = bytes.fromhex(h)
        tag_ok = hmac.new(DK37, blob[16:272], hashlib.sha256).digest() == blob[272:304]
        rec = cbc_decrypt(blob[16:272], blob[:16])
        pr = parse_record(rec)
        kind = kinds[i] if i < len(kinds) else "?%d" % i
        recs[kind] = pr
        nonce12 = (int(pr["a"]).to_bytes(8, "little") + bytes.fromhex(pr["d"]))
        print("%-12s pos=%d tag=%s" % (kind, pos, tag_ok))
        print("   a=%s  d=%s  nonce12=%s" % (pr["a"], pr["d"], nonce12.hex()))
        print("   c=%s" % (pr["c"],))
        print("   e_is_sha0_empty=%s" % (pr["e"] == hashlib.sha256(b"").hexdigest().upper(),))
        print("   H=%s" % pr["b"])
        print("   prefix60=%r" % pr["raw_prefix"])
        print("   tail bytes: %s" % rec[240:].hex())
    import json
    json.dump(recs, open(r"adj7\work\audit_hunt\chls_records_full.json", "w"), indent=1)
    print("\nwrote adj7\\work\\audit_hunt\\chls_records_full.json")


if __name__ == "__main__":
    main()
