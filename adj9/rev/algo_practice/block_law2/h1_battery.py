"""h1_battery.py — H1 ladder: is block a SHA-256-family MAC like the digest?

Wide battery over the probe corpus (r0 base, r2 seed, r3 claim, r4 seed2) —
4 distinct (S, claims) pairs. Any law must match ALL of them.
Run: python h1_battery.py
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALG = os.path.dirname(HERE)
REV = os.path.dirname(ALG)
sys.path.insert(0, REV)
sys.path.insert(0, ALG)

from probe_runs import BASE_CLAIMS  # noqa: E402
from desc10_law import build_desc10  # noqa: E402

DK = bytes.fromhex("690f60944dddd9847db55cd7d2b576b3"
                   "0451723fbcfa92df62b55f6fec60f2de")
IPAD = b"\x36" * 32
OPAD = b"\x5c" * 32


def case(tag):
    d = json.load(open(os.path.join(ALG, "probes", "run_%s.json" % tag)))
    seed = d["seed"]
    claims = dict(BASE_CLAIMS)
    if tag == "r3_claim":
        claims["app_version"] = "3.14.1"
    raw = build_desc10(claims, "session").encode("latin1")
    padded = raw + b"\x00" * (-len(raw) % 4)
    d0 = b"".join(struct.pack(">I", int(x, 16)) for x in d["d0"])
    d4 = b"".join(struct.pack(">I", int(x, 16)) for x in d["d4"])
    S = struct.pack(">I", seed)
    Sl = struct.pack("<I", seed)
    m = {
        "claims": raw, "claims_p": padded, "d0": d0, "d4": d4,
        "S": S, "S_le": Sl, "d2": bytes.fromhex(d["d2"]),
        "len_le": struct.pack("<I", len(raw)),
        "len_be": struct.pack(">I", len(raw)),
    }
    return d["tag"], bytes.fromhex(d["block_hex"]), m


def mats(cases):
    """All pairwise/triple compositions of the base materials."""
    keys = list(cases[0][2].keys())
    out = {}
    for a in keys:
        out[a] = lambda m, a=a: m[a]
    for a in keys:
        for b in keys:
            out["%s+%s" % (a, b)] = lambda m, a=a, b=b: m[a] + m[b]
            out["%s|%s" % (a, b)] = lambda m, a=a, b=b: m[a] + m[b]
    return out


def main():
    cases = [case(t) for t in ("r0_base", "r2_seed", "r3_claim", "r4_seed2")]
    for tag, blk, m in cases:
        print("%-9s block=%s claims=%dB S=%s" %
              (tag, blk.hex(), len(m["claims"]), m["S"].hex()))

    sha256 = lambda b: hashlib.sha256(b).digest()
    ipad_law = lambda K, b: sha256(bytes(a ^ 0x36 for a in K) + b"\x36" * 32
                                   + b)
    # digest-law form: inner=(K^ipad)||ipad||body ; outer=(K^opad)||opad||inner
    digest_law = lambda K, b: sha256(bytes(a ^ 0x5C for a in K) + b"\x5c" * 32
                                    + ipad_law(K, b))
    two_pass_pad = lambda K, b: sha256(bytes(a ^ 0x36 for a in K) + b"\x36" * 32
                                       + b + b"\x36" * 32)

    keys = [k for k, _ in mats(cases).items()]
    hits = []

    def try_law(name, fn):
        ok = sum(1 for tag, blk, m in cases if fn(m) == blk)
        if ok:
            hits.append((ok, name))
        return ok

    print("\n== phase A: plain digests over every composition ==")
    simple = {
        "sha256": sha256,
        "sha256.2x": lambda b: sha256(b) + sha256(sha256(b)),
        "sha1x2": lambda b: hashlib.sha1(b).digest() * 2,
        "sha1x2b": lambda b: hashlib.sha1(b).digest() * 2,
        "md5x2": lambda b: hashlib.md5(b).digest() * 2,
        "blake2s": lambda b: hashlib.blake2s(b).digest(),
        "sha512lo": lambda b: hashlib.sha512(b).digest()[:32],
        "sha3_256": lambda b: hashlib.sha3_256(b).digest(),
    }
    for kn, kf in simple.items():
        for cn in keys:
            try_law("%s(%s)" % (kn, cn), lambda m, f=kf, c=cn: f(mats(cases)[c](m)))

    print("== phase B: HMAC / two-pass pad forms ==")
    keyers = {
        "DK": lambda m: DK, "S": lambda m: m["S"], "S_le": lambda m: m["S_le"],
        "d4": lambda m: m["d4"], "d0": lambda m: m["d0"], "d4[:16]":
            lambda m: m["d4"][:16], "d0[:16]": lambda m: m["d0"][:16],
        "sha256(d4)": lambda m: sha256(m["d4"]),
        "sha256(S||claims)": lambda m: sha256(m["S"] + m["claims"]),
    }
    for kn, kf in keyers.items():
        for cn in ("claims", "claims_p", "S+claims", "claims+S", "d4+claims",
                   "claims+d4", "S+claims_p", "d0+claims", "S"):
            try_law("digestlaw(K=%s, m=%s)" % (kn, cn),
                    lambda m, k=kf, c=cn: digest_law(k(m), mts(c, m)))
            try_law("ipad_only(K=%s, m=%s)" % (kn, cn),
                    lambda m, k=kf, c=cn: ipad_law(k(m), mts(c, m)))
            try_law("hmac(K=%s, m=%s)" % (kn, cn),
                    lambda m, k=kf, c=cn: hmac.new(k(m), mts(c, m),
                                                   hashlib.sha256).digest())
            try_law("twopad(K=%s, m=%s)" % (kn, cn),
                    lambda m, k=kf, c=cn: two_pass_pad(k(m), mts(c, m)))

    print("\n== hits (n/%d) ==" % len(cases))
    for ok, n in sorted(hits, reverse=True):
        print("  %-45s %d/%d" % (n, ok, len(cases)))
    if not hits:
        print("  none")


def mts(name, m):
    return mats([("", b"", m)]).get(name, lambda m: m[name])(m)


if __name__ == "__main__":
    main()