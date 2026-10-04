"""k_hunt.py — offline hunt for the digest HMAC key K (=KPAD_IN).

digest = sha256((K^opad) || opad || sha256((K^ipad) || ipad || body))
with ipad = 36363636*8, opad = 5c5c5c5c*8, body = blob[16:160).
Try K = sha256/simple-derivation of known inputs.
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
AP = os.path.dirname(HERE)
REV = os.path.dirname(AP)
sys.path.insert(0, REV)
sys.path.insert(0, AP)

import F as FP
from desc10_law import build_desc10
from header_gen import make_header

K = bytes.fromhex("690f60944dddd9847db55cd7d2d576b30451723fbcfa92df62b55f6fec60f2de")

SEC = 1790625704
SEED = 0xA6DA5D2B
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")

BASE_CLAIMS = json.load(open(os.path.join(HERE, "base_claims.json")))


def region_bytes():
    d0w, d2w, d4w = FP.region(SEED, 0, 0, head=(0x2B, 0x48))
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    d2 = struct.pack(">I", d2w)
    return d0, d2, d4, d0w, d2w, d4w


def cands():
    raw = build_desc10(BASE_CLAIMS, "session").encode("latin1")
    padded = raw + b"\x00" * (-len(raw) % 4)
    d0, d2, d4, d0w, d2w, d4w = region_bytes()
    hdr = make_header(SEC)
    s_le = struct.pack("<I", SEED)
    s_be = struct.pack(">I", SEED)
    sec_le = struct.pack("<I", SEC)
    sec_be = struct.pack(">I", SEC)
    out = {
        "d0": d0, "d2": d2, "d4": d4, "d8": D8, "d9": D9,
        "hdr": hdr, "raw10": raw, "padded10": padded,
        "seed_be": s_be, "seed_le": s_le, "sec_be": sec_be, "sec_le": sec_le,
        "d0+d2": d0 + d2, "d2+d4": d2 + d4, "d4+d2": d4 + d2,
        "hdr+d2": hdr + d2, "d2+hdr": d2 + hdr,
        "sec+seed": sec_be + s_be, "seed+sec": s_be + sec_be,
        "empty": b"",
        "d8+d9": D8 + D9,
        "d9+d8": D9 + D8,
    }
    return out


def main():
    cs = cands()
    for n, c in cs.items():
        h = hashlib.sha256(c).digest()
        if h == K:
            print("HIT: K = sha256(%s)" % n)
    # also try sha256 of every 32-B window of each candidate
    for n, c in cs.items():
        for off in range(0, max(1, len(c) - 31)):
            w = c[off:off + 32]
            if hashlib.sha256(w).digest() == K:
                print("HIT: K = sha256(%s[%d:%d])" % (n, off, off + 32))
    # K as sha256 of the d4 words individually? d0 words?
    d0, d2, d4, d0w, d2w, d4w = region_bytes()
    for i, w in enumerate(d4w):
        b = struct.pack(">I", w)
        if hashlib.sha256(b).digest() == K:
            print("HIT: K = sha256(d4w[%d])" % i)
    for i, w in enumerate(d0w):
        b = struct.pack(">I", w)
        if hashlib.sha256(b).digest() == K:
            print("HIT: K = sha256(d0w[%d])" % i)
    # is K maybe an HMAC itself with zero key?
    ip = b"\x36" * 32
    op = b"\x5c" * 32
    for n, c in cs.items():
        inner = hashlib.sha256(ip + c).digest()
        outer = hashlib.sha256(op + inner).digest()
        if outer == K:
            print("HIT: K = hmac-sha256(key=0, msg=%s) [standard]" % n)
        inner2 = hashlib.sha256((bytes(32) ^ False) if False else bytes(32))
        # custom variant: sha256((0^ipad)||ipad||c)
        ci = hashlib.sha256(ip + ip + c).digest()
        co = hashlib.sha256(op + op + ci).digest()
        if co == K:
            print("HIT: K = custom-hmac(0, %s)" % n)
    print("k_hunt done (no hits printed => none matched)")


if __name__ == "__main__":
    main()
