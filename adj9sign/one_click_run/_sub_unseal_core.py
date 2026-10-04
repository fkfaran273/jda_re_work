"""_sub_unseal_core.py — whiten_inverse (exact inverse of adj9 whiten_forward)
plus validation: (a) 1000 random round-trips, (b) the 9 embedded Android gold
vectors unsealed and layout-checked.

Read-only w.r.t. adj9_signer.py: everything is imported, nothing modified.

Round structure (from adj9_signer source, PART 5):

    whiten_chunk(chunk, wa):
        x = chunk ^ wa                      # CBC IV = header / prev ciphertext
        for r in 0..13:
            x ^= ROUND_KEYS[r]              # KB[16r:16r+16]
            x =  SBOX(x)                    # AES S-box, bytewise
            x =  PI(x)                      # out[_PI[i]] = in[i]
            if r < 13: x = F(x)             # GF(2) linear mix, 4 LE words
        x ^= FINAL_KEY                      # KB[224:240]
        return x

    whiten_forward: 9 chunks; wa_0 = header, wa_k = ciphertext[k-1].

Inverse: run the chunk backwards (F^-1, PI^-1, SBOX^-1, key XOR in reverse
order, final-key XOR first, CBC IV XOR last).  F is GF(2)-linear (invert the
32x32 bit matrix of F_ROWS by Gaussian elimination); PI is a rotation
(invert the index map directly); SBOX is a bijection (inverse table).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import struct
import sys

import adj9_signer as sg

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- inverses
SBOX = sg.SBOX
SBOX_INV = [0] * 256
for _i, _v in enumerate(SBOX):
    SBOX_INV[_v] = _i
assert sorted(SBOX_INV) == list(range(256)), "SBOX not bijective"

_PI = sg._PI
assert sorted(_PI) == list(range(16)), "PI not a permutation"


def _pi1_inv(chunk):
    """Inverse of sg._pi1 (out[_PI[i]] = in[i])  ->  in[i] = out[_PI[i]]."""
    return bytes(chunk[_PI[i]] for i in range(16))


def _gf2_invert(rows):
    """Invert a 32x32 GF(2) bit matrix given as 32 row masks (row j is the
    mask producing output bit j).  Returns the 32 row masks of the inverse,
    or None if singular."""
    n = 32
    aug = [(rows[j], 1 << j) for j in range(n)]      # (row_mask, tag)
    for col in range(n):
        piv = None
        for i in range(col, n):
            if (aug[i][0] >> col) & 1:
                piv = i
                break
        if piv is None:
            return None
        aug[col], aug[piv] = aug[piv], aug[col]
        for i in range(n):
            if i != col and (aug[i][0] >> col) & 1:
                aug[i] = (aug[i][0] ^ aug[col][0], aug[i][1] ^ aug[col][1])
    return [aug[j][1] for j in range(n)]


F_ROWS = sg.F_ROWS
F_ROWS_INV = _gf2_invert(list(F_ROWS))
assert F_ROWS_INV is not None, "F matrix is singular — cannot invert"

_F_TAB_INV = sg._byte_tables(F_ROWS_INV)


def _F_inv_chunk(chunk):
    """Inverse of sg._F on a 16-B chunk (4 little-endian words)."""
    return b"".join(
        sg._apply_tab(_F_TAB_INV, int.from_bytes(chunk[4 * b:4 * b + 4],
                                                 "little")).to_bytes(4, "little")
        for b in range(4))


def _fast_F_inv_tab(tab, x):
    return sg._apply_tab(tab, x)


def whiten_chunk_inverse(chunk, wa):
    """Exact inverse of sg.whiten_chunk."""
    x = sg._xor(chunk, sg._FINAL_KEY)
    for r in range(13, -1, -1):
        if r < 13:
            x = _F_inv_chunk(x)
        x = _pi1_inv(x)
        x = bytes(SBOX_INV[v] for v in x)
        x = sg._xor(x, sg._ROUND_KEYS[r])
    return sg._xor(x, wa)


def whiten_inverse(body, header):
    """Exact inverse of sg.whiten_forward: body(144) + header(16) -> record."""
    if len(body) != 144 or len(header) != 16:
        raise ValueError("need body=144 B, header=16 B")
    rec = bytearray()
    wa = header
    for k in range(9):
        c = body[16 * k:16 * k + 16]
        rec += whiten_chunk_inverse(c, wa)
        wa = c                       # CBC chain uses the CIPHERTEXT chunk
    return bytes(rec)


# ---------------------------------------------------------------- helpers
SHA0 = hashlib.sha256(b"").digest()


def record_constant_checks(rec):
    """The record layout laws of build_record (PART 7)."""
    return {
        "magic_rec0_2_is_010008": rec[0:3] == b"\x01\x00\x08",
        "sep19_is_0x02": rec[19] == 0x02,
        "sep24_is_0x03": rec[24] == 0x03,
        "sep45_is_0x04": rec[45] == 0x04,
        "sep78_is_0x05": rec[78] == 0x05,
        "sha256_empty_at_79_110": rec[79:111] == SHA0,
        "sep111_113_is_060107": rec[111:114] == b"\x06\x01\x07",
        "zero14_at_114_127": rec[114:128] == b"\x00" * 14,
        "zero2_at_128_129": rec[128:130] == b"\x00\x00",
        "tail_0e14_at_130_143": rec[130:144] == b"\x0e" * 14,
    }


# ------------------------------------------------- (2a) round-trip test
def round_trip_test(n=1000, seed=0xAD9):
    rng = random.Random(seed)
    fails = 0
    for _ in range(n):
        rec = bytes(rng.getrandbits(8) for _ in range(144))
        hdr = bytes(rng.getrandbits(8) for _ in range(16))
        body = sg.whiten_forward(rec, hdr)
        if whiten_inverse(body, hdr) != rec:
            fails += 1
    return n, fails


# --------------------------------------- (2b) Android gold-vector unseal
def gold_unseal_test():
    results = []
    all_ok = True
    for idx, g in enumerate(sg.GOLD_VECTORS):
        blob = bytes.fromhex(g["blob_hex"])
        header = blob[:16]
        body = blob[16:160]
        digest = blob[160:192]
        head = tuple(g["head"])

        # forward: the signer must mint this blob byte-exactly
        mint = sg.sign_pure(g["second"], g["S"], g["map"],
                            d9_hex=g["d9_hex"], kind=g["kind"], head=head)
        mint_ok = (mint == blob)

        # header law
        hdr_ok = header == sg.make_header(g["second"])

        # digest law (double-padded MAC)
        dig_ok = sg.predict_digest(body) == digest

        # unseal + rebuild
        rec = whiten_inverse(body, header)
        claims = sg.build_claims(g["map"], g["kind"])
        rebuilt = sg.build_record(g["S"], sg.head16_for(g["S"], head),
                                  claims, bytes.fromhex(g["d9_hex"]))
        rec_ok = rec == rebuilt
        checks = record_constant_checks(rec)
        cert_ok = rec[25:45].hex() == g["d9_hex"]
        ok = mint_ok and hdr_ok and dig_ok and rec_ok and cert_ok \
            and all(checks.values())
        all_ok &= ok
        results.append({
            "idx": idx, "app": g["app"], "kind": g["kind"],
            "S": g["S"], "second": g["second"], "head": list(head),
            "mint_byte_exact": mint_ok, "header_law_ok": hdr_ok,
            "digest_ok": dig_ok, "record_rebuild_ok": rec_ok,
            "cert_sha1_match": cert_ok, "constants": checks,
            "cert_sha1_hex": rec[25:45].hex(),
            "S_field_hex": rec[20:24].hex(),
            "d0_head_hex": rec[3:19].hex(),
            "ok": ok,
        })
    return all_ok, results


def main():
    out = {"module": "whiten_inverse validation"}

    n, fails = round_trip_test(1000)
    out["round_trip"] = {"n": n, "failures": fails,
                         "ok": fails == 0}
    print("[unseal] round-trip: %d/%d OK  -> %s"
          % (n - fails, n, "OK" if fails == 0 else "FAIL"))

    all_ok, gold = gold_unseal_test()
    out["gold_vectors"] = gold
    out["gold_all_ok"] = all_ok
    for g in gold:
        print("[unseal] gold %-9s %-11s S=%-10u mint=%s hdr=%s dig=%s "
              "rec=%s const=%s cert=%s"
              % (g["app"], g["kind"], g["S"],
                 "OK" if g["mint_byte_exact"] else "FAIL",
                 "OK" if g["header_law_ok"] else "FAIL",
                 "OK" if g["digest_ok"] else "FAIL",
                 "OK" if g["record_rebuild_ok"] else "FAIL",
                 "OK" if all(g["constants"].values()) else "FAIL",
                 "OK" if g["cert_sha1_match"] else "FAIL"))

    with open(os.path.join(HERE, "_sub_unseal_core_out.json"), "w") as f:
        json.dump(out, f, indent=1)
    print("[unseal] VALIDATION %s" % ("PASS" if (fails == 0 and all_ok)
                                      else "FAIL"))
    return 0 if (fails == 0 and all_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
