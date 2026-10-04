"""adj9_decode.py -- recovering a record from a captured signature.

adj9_pure.py only signs.  These two functions go the other way: they undo the
whitening cipher so a gate can pull the 144-byte record back out of a genuine
192-byte blob, and read the seed, cert and head phase out of it.

Inverting a cipher needs the inverse of each step, so this is a separate walk
rather than something composed from encrypt.  The signer never needs inverses,
so they are derived here from the same GF(2^8) arithmetic; only KB is recorded.

    import adj9_decode as D, adj9_pure as P
    record = D.whiten_body_inverse(blob[16:160], blob[:16])

Verify it still agrees with the signer:
    python adj9_decode.py
"""
import sys

import adj9_pure as P

from adj9_pure import KB, T, _SBOX_MASK, _gmul

# the inverse S-box, derived from the forward one
T_INV = [0] * 256
for _x, _v in enumerate(T):
    T_INV[_v] = _x

# ShiftRows and its inverse: byte i is row i%4, column i//4; row r rotates
# left by r.  The forward round does out[PI[i]] = in[i].
PI = [4 * (((i // 4) - (i % 4)) % 4) + (i % 4) for i in range(16)]


def _inv_shift_rows(chunk):
    """Undo out[PI[i]] = in[i]."""
    return bytes(chunk[PI[i]] for i in range(16))


def _inv_mix_chunk(chunk):
    """AES InvMixColumns per little-endian word:
    v_b = 14*b_b ^ 11*b_(b+1) ^ 13*b_(b+2) ^ 9*b_(b+3)."""
    def imc(word):
        b = [(word >> 8 * i) & 0xFF for i in range(4)]
        out = 0
        for i in range(4):
            out |= (_gmul(14, b[i]) ^ _gmul(11, b[(i + 1) % 4])
                    ^ _gmul(13, b[(i + 2) % 4]) ^ _gmul(9, b[(i + 3) % 4])) << 8 * i
        return out
    return b"".join(imc(int.from_bytes(chunk[4 * i:4 * i + 4], "little"))
                    .to_bytes(4, "little") for i in range(4))


# ==========================================================================

def whiten_inverse(chunk, WA, KB_=None, T_inv=None, pi1_inv=None, F_inv=None):
    """Invert one 16-byte chunk given its WA (the previous chunk, or the
    header for chunk 0).  Decode-side only; signing uses encrypt."""
    kb = KB if KB_ is None else KB_
    tinv = T_INV if T_inv is None else T_inv
    pinv = _inv_shift_rows if pi1_inv is None else pi1_inv
    finv = _inv_mix_chunk if F_inv is None else F_inv
    x = bytes(v ^ 0x55 ^ kb[224 + i] for i, v in enumerate(chunk))  # final sweep
    for r in range(13, -1, -1):
        if r < 13:
            x = finv(x)                       # undo diag-2 affine
        x = pinv(x)                           # undo diag-1 permutation
        x = bytes(tinv[v ^ _SBOX_MASK] for v in x)  # undo S-box
        x = bytes(v ^ _SBOX_MASK ^ kb[16 * r + i]
                    for i, v in enumerate(x))
    return bytes(a ^ b for a, b in zip(x, WA))  # remove the WA XOR

def whiten_body_inverse(body, header, KB_=None, T_inv=None, pi1_inv=None,
                        F_inv=None):
    """body: 144 whitened bytes (blob[16:160)), header: blob[0:16).
    Returns the 144-B record."""
    out = bytearray()
    wa = header
    for k in range(len(body) // 16):
        p = whiten_inverse(body[16 * k:16 * k + 16], wa, KB_, T_inv,
                           pi1_inv, F_inv)
        out += p
        wa = body[16 * k:16 * k + 16]
    return bytes(out)


if __name__ == "__main__":
    import random
    r = random.Random(0)
    ok = True
    for _ in range(200):
        rec = bytes(r.getrandbits(8) for _ in range(144))
        hdr = P.make_header(1790341508)
        back = whiten_body_inverse(P.encrypt(rec, hdr), hdr)
        if back != rec:
            ok = False
            break
    print("round-trip 200 random records:", "OK" if ok else "FAIL")
    sys.exit(0 if ok else 1)
