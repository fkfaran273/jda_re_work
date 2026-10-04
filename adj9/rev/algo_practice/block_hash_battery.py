"""block_hash_battery.py — is the 32-B block a plain hash of known inputs?

The block does NOT depend on the signing second (probe r1/r5) but does on
S/region and claims (r2/r3/r4). 32 B = exactly hash-sized. Battery over the
known inputs, validated across r0 + r2 + r3 (3 different (S, claims) pairs).
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(HERE)
sys.path.insert(0, REV)
import F as FP  # noqa: E402
from probe_runs import BASE_CLAIMS  # noqa: E402
from desc10_law import build_desc10  # noqa: E402


def inputs_for(seed, claims):
    raw = build_desc10(claims, "session").encode("latin1")
    padded = raw + b"\x00" * (-len(raw) % 4)
    d0w, d2w, d4w = FP.region(seed, 0, 0, head=(0x2B, 0x48))
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    S4 = struct.pack(">I", seed)
    return {
        "claims_raw": raw, "claims_padded": padded,
        "d0": d0, "d4": d4, "d0+d4": d0 + d4, "d4+d0": d4 + d0,
        "S+claims": S4 + raw, "claims+S": raw + S4,
        "S+d0": S4 + d0, "d0+claims": d0 + raw, "claims+d4": raw + d4,
        "S+d4": S4 + d4, "d4+S": d4 + S4,
        "S*2": S4 * 2, "d2+d4": struct.pack(">I", d2w) + d4,
        "claims+S+d4": raw + S4 + d4, "S+claims+d4": S4 + raw + d4,
    }


FNS = {
    "sha256": lambda b: hashlib.sha256(b).digest(),
    "sha1x2": lambda b: hashlib.sha1(b).digest() * 2,
    "md5x2": lambda b: hashlib.md5(b).digest() * 2,
    "blake2s": lambda b: hashlib.blake2s(b).digest(),
    "sha512[:32]": lambda b: hashlib.sha512(b).digest()[:32],
    "sha1[:20]+sha256[:12]": lambda b: hashlib.sha1(b).digest()
    + hashlib.sha256(b).digest()[:12],
}


def main():
    cases = []
    for tag in ("r0_base", "r2_seed", "r3_claim", "r4_seed2"):
        d = json.load(open(os.path.join(HERE, "probes", "run_%s.json" % tag)))
        seed = d["seed"]
        claims = dict(BASE_CLAIMS)
        if tag == "r3_claim":
            claims["app_version"] = "3.14.1"
        cases.append((tag, bytes.fromhex(d["block_hex"]),
                      inputs_for(seed, claims)))

    # consistency first: any (fn, input) matching ALL cases?
    for fn_name, fn in FNS.items():
        for cn in cases[0][2]:
            if all(fn(ins[cn]) == blk for tag, blk, ins in cases):
                print("HIT ALL: %s(%s)" % (fn_name, cn))
                return
    # single-case hits (then we check why they fail others)
    for tag, blk, ins in cases:
        for fn_name, fn in FNS.items():
            for cn, cb in ins.items():
                if fn(cb) == blk:
                    print("HIT %s only: %s(%s)" % (tag, fn_name, cn))
    print("battery done — no universal plain-hash law")


if __name__ == "__main__":
    main()
