"""_sub_np_sha256.py — numpy-vectorized SHA-256 (batch of messages sharing a
prefix block) with the custom IV2, validated byte-exact against
adj9_signer.sha256_iv2.

API:
    batch_digests(prefix64, rests) -> (N, 8) uint32 final state words
        prefix64 : 64 bytes  (message[0:64], constant across the batch)
        rests    : (N, T) uint8 — message[64:] WITH standard padding already
                   appended (0x80, zeros, BE64 bit length of the FULL message).
"""
import numpy as np
import struct

import adj9_signer as sg

_K = np.array(sg._K256, dtype=np.uint32)
_IV2_STATE = np.array(struct.unpack(">8I", sg.IV2), dtype=np.uint32)


def _rotr(x, n):
    return (x >> np.uint32(n)) | (x << np.uint32(32 - n))


def compress_batch(state, blk):
    """state (N,8) uint32, blk (N,16) uint32 -> new (N,8) uint32."""
    N = blk.shape[0]
    w = np.empty((N, 64), dtype=np.uint32)
    w[:, :16] = blk
    for i in range(16, 64):
        x15 = w[:, i - 15]
        x2 = w[:, i - 2]
        s0 = _rotr(x15, 7) ^ _rotr(x15, 18) ^ (x15 >> np.uint32(3))
        s1 = _rotr(x2, 17) ^ _rotr(x2, 19) ^ (x2 >> np.uint32(10))
        w[:, i] = w[:, i - 16] + s0 + w[:, i - 7] + s1
    a = state[:, 0].copy()
    b = state[:, 1].copy()
    c = state[:, 2].copy()
    d = state[:, 3].copy()
    e = state[:, 4].copy()
    f = state[:, 5].copy()
    g = state[:, 6].copy()
    h = state[:, 7].copy()
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = h + S1 + ch + _K[i] + w[:, i]
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = S0 + maj
        h[:] = g
        g[:] = f
        f[:] = e
        e[:] = d + t1
        d[:] = c
        c[:] = b
        b[:] = a
        a[:] = t1 + t2
    out = np.empty_like(state)
    out[:, 0] = state[:, 0] + a
    out[:, 1] = state[:, 1] + b
    out[:, 2] = state[:, 2] + c
    out[:, 3] = state[:, 3] + d
    out[:, 4] = state[:, 4] + e
    out[:, 5] = state[:, 5] + f
    out[:, 6] = state[:, 6] + g
    out[:, 7] = state[:, 7] + h
    return out


def batch_digests(prefix64, rests, batch=65536):
    """prefix64: bytes(64); rests: (N,T) uint8 WITH padding appended.
    Returns (N,8) uint32."""
    N = rests.shape[0]
    st0 = sg._compress(list(struct.unpack(">8I", sg.IV2)),
                       list(struct.unpack(">16I", prefix64)))
    base = np.array(st0, dtype=np.uint32)
    out = np.empty((N, 8), dtype=np.uint32)
    for lo in range(0, N, batch):
        hi = min(lo + batch, N)
        n = hi - lo
        state = np.broadcast_to(base, (n, 8)).copy()
        r = rests[lo:hi]
        nb = r.shape[1] // 64
        for bi in range(nb):
            blk = r[:, bi * 64:(bi + 1) * 64].view(">u4").astype(np.uint32)
            state = compress_batch(state, blk)
        out[lo:hi] = state
    return out


def pad_rest(msg_rest, total_len):
    """msg_rest: bytes (message[64:]); total_len: full message length.
    Returns padded bytes with len % 64 == 0."""
    m = msg_rest + b"\x80" + b"\x00" * ((55 - total_len) % 64) \
        + struct.pack(">Q", total_len * 8)
    assert len(m) % 64 == 0
    return m


def validate(n=300):
    import random
    rng = random.Random(1234)
    for _ in range(n):
        L = rng.randrange(0, 600)
        msg = bytes(rng.getrandbits(8) for _ in range(L))
        if L <= 64:
            continue
        want = sg.sha256_iv2(msg)
        words = np.frombuffer(want, ">u4").astype(np.uint32)
        prefix = msg[:64]
        rest = pad_rest(msg[64:], L)
        got = batch_digests(prefix, np.frombuffer(rest, np.uint8)
                            .reshape(1, -1).copy())[0]
        if not np.array_equal(got, words):
            print("MISMATCH at L=%d" % L)
            return False
    return True


if __name__ == "__main__":
    ok = validate()
    print("numpy sha256_iv2 validation:", "OK" if ok else "FAIL")
