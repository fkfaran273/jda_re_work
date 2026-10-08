"""commit2_hunt.py — the SOLVED 3.62.0 claims-commitment law (c20, c32).

Law (verified byte-exact on mints A, C and a fresh mint D at a new second
with a third claims variant — see COMMIT_FINDINGS.md):

  IV0    = 16ba6d02 11a298c2 82187e46 4c148c22 3a5cbc15 06519f14 97b9e370 08ec3bec
           (constant for this device/app; output of an earlier register-hash
            chained from sha256(b"") — see findings section 4)
  msg    = 00*40 || d666bf3444ddccca7eada76a || ASCIIhex-upper(sha256(b""))
           || claims                                  (460 B for 344-B claims)
  padded = msg || 80 00.. || BE64(8*len(msg))                     (512 B)
  state  = IV0
  for each 64-B block:  state = SHA256-compress(state, block)  (STANDARD
                        rounds + Davies-Meyer feed-forward add)
  H      = final digest (standard chaining throughout)
  c20    = LE-word-encode(H[12:32])          (20 B, stored word-swapped)
  c32    = LE-word-encode(H - H_prev)  where H_prev = the chaining value
           before the last block (== the last block's raw working vars)

    python commit2_hunt.py
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "adj7_work"))

M = 0xFFFFFFFF
K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
     0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
     0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
     0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
     0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
     0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

IV0 = [0x16ba6d02, 0x11a298c2, 0x82187e46, 0x4c148c22,
       0x3a5cbc15, 0x06519f14, 0x97b9e370, 0x08ec3bec]
PREFIX12 = bytes.fromhex("d666bf3444ddccca7eada76a")


def _S1(x):
    return ((x >> 6 | x << 26) & M) ^ ((x >> 11 | x << 21) & M) ^ ((x >> 25 | x << 7) & M)


def _S0(x):
    return ((x >> 2 | x << 30) & M) ^ ((x >> 13 | x << 19) & M) ^ ((x >> 22 | x << 10) & M)


def _ch(e, f, g):
    return (e & f) ^ (~e & g & M)


def _maj(a, b, c):
    return (a & b) ^ (a & c) ^ (b & c)


def rounds(state, blk):
    """One standard SHA-256 compression (rounds + feed-forward add)."""
    w = list(blk)
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = ((x >> 7 | x << 25) & M) ^ ((x >> 18 | x << 14) & M) ^ (x >> 3)
        s1 = ((y >> 17 | y << 15) & M) ^ ((y >> 19 | y << 13) & M) ^ (y >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & M)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        t1 = (h + _S1(e) + _ch(e, f, g) + K[i] + w[i]) & M
        t2 = (_S0(a) + _maj(a, b, c)) & M
        h, g, f = g, f, e
        e = (d + t1) & M
        d, c, b = c, b, a
        a = (t1 + t2) & M
    return [(x + st) & M for x, st in zip((a, b, c, d, e, f, g, h), state)]


def le_words(words):
    """The native stores every dword byte-swapped (LE) in memory."""
    return b"".join(w.to_bytes(4, "little") for w in words)


def commitments(claims, iv0=IV0, prefix12=PREFIX12):
    """Return (c20, c32, H_final_words) for one claims string."""
    msg = (b"\x00" * 40 + prefix12 +
           hashlib.sha256(b"").hexdigest().upper().encode() + claims)
    padded = (msg + b"\x80" + b"\x00" * ((55 - len(msg) % 64) % 64) +
              struct.pack(">Q", len(msg) * 8))
    state = list(iv0)
    prev = None
    for i in range(0, len(padded), 64):
        prev = state
        state = rounds(state, list(struct.unpack(">16I", padded[i:i + 64])))
    c20 = le_words(state[3:8])
    c32 = le_words([(x - y) & M for x, y in zip(state, prev)])
    return c20, c32, state


def main():
    import adj7_signer as sg
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(ROOT, "adj7_work", "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])

    targets = {
        "A": ("6cffea5110a9940910e85257b51dc608c577c522",
              "095ccb389439543bf3bad2abc05e42aab2994c5a7c2084aeeb899e6d1ee1656b",
              sg.build_claims("session", params)),
        "C": ("40be5d7051dc85a45bec0d823269547ed52d64de",
              "a8c5b456892afa100bb79c30b9aa5cf001ff667982fa436e80c8cab393fd1f65",
              sg.build_claims("session", dict(params, app_version="9.9.9"))),
        "D": ("ada5183c6e3460b58e896eaa71b795f17e903956",
              "c390048a36df99c3592dc5258201e2dfb1575185e7e015ad6d8b9bbf86e507c9",
              sg.build_claims("session", dict(params, app_version="7.7.7"))),
    }
    ok = True
    for tag, (t20, t32, claims) in targets.items():
        c20, c32, H = commitments(claims)
        m20, m32 = c20.hex() == t20, c32.hex() == t32
        ok &= m20 and m32
        print("%s: c20 %s %s\n   c32 %s %s\n   H  %s"
              % (tag, c20.hex(), "OK" if m20 else "FAIL",
                 c32.hex(), "OK" if m32 else "FAIL",
                 " ".join("%08x" % x for x in H)))

    # cross-check against the heap snapshots when present
    HEAP = 0x9000000
    for tag, fn in (("A", "snap_A.bin"), ("C", "snap_C.bin"),
                    ("D", "commit2_snap_D.bin")):
        p = os.path.join(HERE, fn)
        if not os.path.exists(p):
            continue
        snap = open(p, "rb").read()
        c20, c32, _ = commitments(targets[tag][2])
        h20 = snap[0x900bb84 - HEAP:0x900bb84 - HEAP + 20]
        h32 = snap[0x900be98 - HEAP:0x900be98 - HEAP + 32]
        print("snap %s: heap c20 %s  heap c32 %s  %s"
              % (tag, h20.hex(), h32.hex(),
                 "OK" if (h20 == c20 and h32 == c32) else "MISMATCH"))

    print("\nLAW " + ("VERIFIED" if ok else "BROKEN"))


if __name__ == "__main__":
    main()
