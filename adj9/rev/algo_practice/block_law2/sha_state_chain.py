"""sha_state_chain.py — test whether the block = standard SHA-256 chain.

Reads digest_law/digest_emits.json (full emit trace with VM step numbers for the
r0 synthetic run) and:
  * locates the SHA-256 IV push (6a09e667..) and the 8 compression outputs
    at MAIN idx 685..692 (top=620)
  * extracts the 16-word message block staged at MAIN idx 821..836 for each round
  * runs a standard SHA-256 compression and checks byte-exactness
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALG = os.path.dirname(HERE)
EM = json.load(open(os.path.join(ALG, "digest_law", "digest_emits.json")))
MAIN = 0x5450001000

K = [
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
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
M32 = 0xFFFFFFFF


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def compress(state, block):
    """block = 16 big-endian dwords"""
    w = list(block[:16])
    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & M32)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + K[i] + w[i]) & M32
        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        mj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + mj) & M32
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & M32, c, b, a, (t1 + t2) & M32
    return [(x + y) & M32 for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def main():
    # locate the IV write (step of idx 685 == 6a09e667) and the 8 output rounds
    iv_step = None
    rounds = []
    for (st, sva, top, n, v, idx) in EM:
        if sva != MAIN or top != 620:
            continue
        if n == 65 and v == IV[0] and iv_step is None:
            iv_step = st
        if n == 65 and st > 40000 and v not in (0x36363636, 0x5C5C5C5C):
            rounds.append((st, v))
    print("IV write step:", iv_step)
    print("round starts (idx685 writes after IV):", [(s, "%08x" % v) for s, v in rounds][:20])

    # build MAIN snapshots at chosen steps
    want = [iv_step] + [r[0] for r in rounds[:9]]
    snaps = []
    cur = {}
    ri = 0
    for (st, sva, top, n, v, idx) in EM:
        if sva != MAIN:
            continue
        cur[idx] = v
        while ri < len(want) and st >= want[ri]:
            snaps.append((want[ri], dict(cur)))
            ri += 1
    while ri < len(want):
        snaps.append((want[ri], dict(cur)))
        ri += 1

    print("\n== per-round message block (MAIN idx 821..836) ==")
    for s, M in snaps:
        words = [M.get(820 + 1 + i, 0) for i in range(16)]
        raw = b"".join(struct.pack(">I", w) for w in words)
        printable = sum(1 for b in raw if 32 <= b < 127)
        print("step %8d  %s  (%d/%d printable)"
              % (s, raw.hex(), printable, len(raw)))
    return snaps, rounds


if __name__ == "__main__":
    main()
