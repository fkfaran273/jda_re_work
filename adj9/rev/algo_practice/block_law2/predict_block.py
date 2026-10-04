"""predict_block.py — the adj9 block law: record[46:78) in closed form.

    D9    = fad0f10d60f93c17937b2f1eb6c09691ae7d74bd     (APK cert SHA-1,
                                                          record[25:45])
    IV2   = eba2c4350f4002dc9fa8dac5127035ba
            7a30ed9323473054bbe3cd00f1355ea5             (VM hardcoded IV)

    msg   = D9
            || record[1:19]          (00 08 || 16-byte d0 head)
            || LE32(S)              (S = BE32(record[20:24]))
            || SHA256("")           (32 B)
            || 01 00 00 ... 00      (17 B: 0x01 + 16 zeros)
            || claims               (desc10 payload, unpadded)
    block = SHA-256 over `msg` with the standard padding but chaining from
            IV2 instead of the standard SHA-256 IV.

Pure Python, no VM.  See LAW.md for the provenance.
"""
from __future__ import annotations

import hashlib
import struct

D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
IV2 = bytes.fromhex("eba2c4350f4002dc9fa8dac5127035ba"
                    "7a30ed9323473054bbe3cd00f1355ea5")
SHA0 = hashlib.sha256(b"").digest()
TAIL = b"\x01" + b"\x00" * 16

M32 = 0xFFFFFFFF
_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2]


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def _compress(state, blk):
    w = list(blk)
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & M32)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        t1 = (h + S1 + ((e & f) ^ (~e & g)) + _K[i] + w[i]) & M32
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) & M32
        h, g, f, e, d, c, b, a = (g, f, e, (d + t1) & M32, c, b, a,
                                  (t1 + t2) & M32)
    return [(x + y) & M32 for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def sha256_iv2(msg: bytes) -> bytes:
    """SHA-256 with the standard padding but the VM's custom IV2."""
    st = list(struct.unpack(">8I", IV2))
    m = msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64) \
        + struct.pack(">Q", len(msg) * 8)
    for i in range(0, len(m), 64):
        blk = [int.from_bytes(m[i + 4 * j:i + 4 * j + 4], "big") for j in range(16)]
        st = _compress(st, blk)
    return struct.pack(">8I", *st)


def block_message(head16: bytes, S: int, claims: bytes, d9: bytes = D9) -> bytes:
    """head16 = record[3:19]; S = the 32-bit F seed (BE32 of record[20:24])."""
    return (d9 + b"\x00\x08" + head16 + struct.pack("<I", S)
            + SHA0 + TAIL + claims)


def predict_block(claims, S, head16=None, d9=D9):
    """claims: bytes (the descriptor-#10 payload, UNPADDED) or a latin-1 str.
       S:      int, the 32-bit F seed = BE32(record[20:24]).
       head16: record[3:19] (16 B, the d0 head). Required.
       d9:     record[25:45], the APK certificate SHA-1.  Per-blob (the penti
               build is fad0f10d..., the creditsea build is 06f5ffce...);
               it is descriptor #9, NOT a universal constant.
    """
    if isinstance(claims, str):
        claims = claims.encode("latin1")
    if head16 is None:
        raise ValueError("head16 (record[3:19]) is required")
    return sha256_iv2(block_message(head16, S, claims, d9))


def predict_block_from_record(record, claims, d9=None):
    """Convenience: take head/S/cert straight out of a decoded 144-B record."""
    if d9 is None:
        d9 = record[25:45]
    return predict_block(claims, int.from_bytes(record[20:24], "big"),
                         record[3:19], d9)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, __file__.rsplit("\\", 1)[0])
    sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("\\", 1)[0])
    print("law loaded; IV2 =", IV2.hex())