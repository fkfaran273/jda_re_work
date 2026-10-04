"""Offline lift of the adj9 native region transform.

The complete descriptor path is reproduced here: the d4 PRNG/shuffle/transpose
slice, the 0x144074 whitening/materializer, and the d2 seed serialization.
"""
from __future__ import annotations

_MASK31 = 0x7FFFFFFF


def _step(x: int) -> int:
    if x == 0:
        x = 0x075BD924
    q = x // 0x1F31D
    y = (x - q * 0x1F31D) * 0x41A7 - q * 0x0B14
    if y < 0:
        y += _MASK31
    return y & _MASK31


def _raw16(seed: int) -> list[int]:
    state = seed & 0xFFFFFFFF
    perm = [0] * 16
    for i in range(16):
        r = _step(state)
        state = r
        j = r % (i + 1)
        perm[i], perm[j] = perm[j], i

    pre = []
    for i in range(16):
        if (i & 1) == 0:
            state = _step(state)
        r = state
        v = (r >> 16) & 0xFFFF if (i & 1) == 0 else r
        pos = 15 - perm[i]
        pre.append(((v & ((1 << pos) - 1)) | (1 << pos)) & 0xFFFF)

    out = [0] * 16
    for j in range(16):
        v = 0
        for i in range(16):
            if pre[i] & (1 << (15 - j)):
                v |= 1 << (15 - i)
        out[j] = v
    return out


def _d4_words(seed: int) -> list[int]:
    raw = _raw16(seed)
    b = b"".join(x.to_bytes(2, "little") for x in raw)
    return [int.from_bytes(b[i:i + 4], "big") for i in range(0, 32, 4)]


def _whitener_word(x1: int, source: list[int]) -> int:
    """Replay one 0x144074 call.

    The native routine starts with an accumulator of zero.  Each set bit b in
    ``(2*x1 + 3) & 0xffff`` XORs the halfword at source index ``7-b``; the
    resulting 16-bit word is written to the call's d0 destination halfword.
    """
    mask = ((x1 << 1) + 3) & 0xFFFF
    value = 0
    for bit in range(8):
        if (mask >> bit) & 1:
            value ^= source[7 - bit]
    return value & 0xFFFF


def _d0_words(d4: list[int]) -> list[int]:
    """Replay the 72-call d0 materializer at 0x144074.

    Calls 0..71 use x1=0x40..0x47 cyclically.  The final twelve calls use the
    captured x1 sequence and overwrite d0[0..11], exactly as the native VM does.
    """
    d4_bytes = b"".join(word.to_bytes(4, "big") for word in d4)
    source = [int.from_bytes(d4_bytes[i:i + 2], "little") for i in range(16, 32, 2)]

    values = [_whitener_word(0x40 + (i & 7), source) for i in range(72)]
    post_x1 = (0x30, 0x2B, 0x34, 0x37, 0x38, 0x3B,
               0x3C, 0x35, 0x36, 0x2D, 0x48, 0x05)
    for i, x1 in enumerate(post_x1):
        values[i] = _whitener_word(x1, source)

    raw = b"".join(value.to_bytes(2, "little") for value in values)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 144, 4)]


def region(V: int, pid: int, tid: int):
    """Return ``(d0, d2, d4)`` as descriptor words.

    Native d2 is the little-endian store of ``S = V ^ (pid << 16)``; descriptor
    words are interpreted big-endian, hence the byte swap below.  The tid is
    not read on this path: the 0x144074 materializer consumes only d4 halfwords
    and the d4 path consumes only the combined seed.
    """
    del tid  # verified absent from the d0/d2 materializer
    key = V & 0xFFFFFFFF
    seed = key ^ ((pid & 0xFFFF) << 16)
    d4 = _d4_words(seed)
    d0 = _d0_words(d4)
    d2 = int.from_bytes((seed & 0xFFFFFFFF).to_bytes(4, "little"), "big")
    return d0, d2, d4


if __name__ == "__main__":
    for v in (0x6AA21400, 0x6AA21401, 0x6AA21402, 0x6AA21403,
              0x6AA215E4, 0x6AAC93A0):
        d0, d2, d4 = region(v, 12345, 12346)
        print(hex(v), [f"{x:08x}" for x in d0[:6]], f"{d2:08x}",
              [f"{x:08x}" for x in d4])
