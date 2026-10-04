"""F — the adj9 per-call region transform (#0 / #2 / #4).

Pure-Python model of the descriptor-region builder in the Adjust Signature SDK
5.0.0 native signer.  Given the fill-instant clock value and the d0 head phase it
reproduces the three entropy-bearing descriptors byte-for-byte.

    region(V, pid, tid, head) -> (d0[36], d2, d4[8])  words are BIG-endian

`V` is the fill-instant value computed by normalizing
`sec * 1_000_000 + usec + 4000` and XORing the resulting second and microsecond.
`pid` enters the native seed; `tid` is accepted for contract compatibility and
is not read on this path.

Native path
-----------

  0x1437b8..0x1437c4  d2 = little-endian store of the seed
  0x1437ec            builder entry; stores the seed, creates the d4 work area
  0x143c88            16-byte zero-initialised shuffle
  0x13dfd0            31-bit PRNG (Schrage step), 16 shuffle draws + 1 per pair
  0x1439c4..0x143a1c  builds 16 pre-transpose halfwords into d4
  0x143d98            16x16 bit-matrix transpose
  0x143f68            d4 stores
  0x144074..0x1441e0  16-bit XOR source-word selector used by d0

The seed is `S = V ^ (pid << 16)`; only the low 16 bits of `pid` are consumed.

The d0 prefix is not copied from the ordinary 72-call cycle.  Its W0 and X
words use a fixed pair of source-word selectors, after which the stable 8-value
halfword cycle resumes.

Head phases (selector sequences that precede the stable cycle):
  * GENUINE device (the real signer, verified 10/10 against the whcap capture
    corpus in all_signings.json):  HEAD_FIRST = (0x22, 0x2E)  -- 9 of 10 rows;
    HEAD_RESIGN = (0x2B, 0x07, 0x22, 0x2E) -- the one re-sign row.  These two
    together reproduce the captured d0 of every genuine signing.
  * The older 12-selector tables below (0x30, 0x2B, 0x34, ...) reproduce the
    SYNTHETIC fill_runs emulator corpus only (0/10 on the genuine corpus).  They
    are retained so verify_d0.py can still check that corpus, but they must NOT
    be used to mint a live request: doing so emits a byte-wrong d0 head.

The phase is per-request state and is not inferable from V/pid/tid/second; it
must be supplied by the caller.
"""

from __future__ import annotations

_MASK31 = 0x7FFFFFFF
_MASK16 = 0xFFFF
_MASK32 = 0xFFFFFFFF

# d0 head phases.  CORRECTED 2026-09-27 against genuine com.penti.app captures
# (mywork/artifacts/rows_full.json): the tables previously labelled GENUINE here
# were the emulator's literals and reproduce the device d0 on 0/3 signings.
# The two DEVICE_* phases below are byte-exact on 3/3 real signings
# (mywork/solve_resign_head.py).  The phase is per-request state and is not
# inferable from V/pid; the caller must supply it.
DEVICE_HEAD_FIRST = (0x2B, 0x22, 0x25, 0x2E, 0x44)          # sign_id 1-2
DEVICE_HEAD_RESIGN = (0x2B, 0x07, 0x22, 0x25, 0x2E, 0x45)    # sign_id 3+

# Aliases: callers across the tree use the old names.  They now point at the
# device-verified phases.
HEAD_FIRST = DEVICE_HEAD_FIRST
HEAD_RESIGN = DEVICE_HEAD_RESIGN

# Legacy SYNTHETIC head phases.  These reproduce only the fill_runs emulator
# corpus (0/10 on genuine captures) and are kept solely so verify_d0.py can
# still check that corpus.  Do not use them for a live request.
SYNTH_HEAD_FIRST = (0x2B, 0x22, 0x25, 0x2E)
SYNTH_HEAD_RESIGN = (0x2B, 0x07, 0x22, 0x25, 0x2E)
# One additional scheduler phase occurs once in fill_runs.  It is retained so
# the saved corpus is byte-exact; it must not be synthesized for a live request
# unless the corresponding runtime phase state is known.
SYNTH_HEAD_RESIGN_ALT = SYNTH_HEAD_RESIGN + (0x4A, 0x05)

_D0_SELECTORS_FIRST = (
    0x30, 0x2B, 0x34, 0x37, 0x38, 0x3B,
    0x3C, 0x35, 0x36, 0x2D, 0x48, 0x05,
)
_D0_SELECTORS_RESIGN = (
    0x30, 0x2B, 0x07, 0x34, 0x37, 0x38, 0x3B,
    0x3C, 0x35, 0x36, 0x2D, 0x48, 0x05,
)
_D0_SELECTORS_RESIGN_ALT = (
    0x30, 0x2B, 0x07, 0x34, 0x37, 0x38, 0x3B,
    0x3C, 0x35, 0x36, 0x2D, 0x48, 0x4A, 0x05,
)


def head_for_sign_id(sign_id: int):
    """Whitener head for a signing ordinal (1-based) within the process."""
    return HEAD_FIRST if sign_id <= 2 else HEAD_RESIGN


def _step(x: int) -> int:
    """One step of the 31-bit Schrage PRNG at 0x13dfd0."""
    if x == 0:
        x = 0x075BD924
    q = x // 0x1F31D
    y = (x - q * 0x1F31D) * 0x41A7 - q * 0x0B14
    if y < 0:
        y += _MASK31
    return y & _MASK31


def _raw16(seed: int) -> list[int]:
    """Shuffle (0x143c88) + pair consumption (0x1439c4) -> 16 pre-transpose halfwords.

    Not Fisher-Yates: the native buffer starts as 16 zero bytes and each draw
    swaps `perm[i]` with `perm[j]`, `j = r % (i + 1)`.  Even output indices take
    the high 16 bits of the state, odd indices the full low-32 value; bit
    position is `15 - perm[i]` with the low bits below it retained.
    """
    state = seed & _MASK32
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
        v = (r >> 16) & _MASK16 if (i & 1) == 0 else r
        pos = 15 - perm[i]
        pre.append(((v & ((1 << pos) - 1)) | (1 << pos)) & _MASK16)
    return pre


def _transpose16(pre: list[int]) -> list[int]:
    """The 16x16 bit-matrix transpose at 0x143d98."""
    out = [0] * 16
    for j in range(16):
        v = 0
        for i in range(16):
            if pre[i] & (1 << (15 - j)):
                v |= 1 << (15 - i)
        out[j] = v
    return out


def _d4_words(seed: int) -> list[int]:
    """Descriptor #4: 8 big-endian words from the little-endian halfword stream."""
    raw = _transpose16(_raw16(seed))
    packed = b"".join(x.to_bytes(2, "little") for x in raw)
    return [int.from_bytes(packed[i:i + 4], "big") for i in range(0, 32, 4)]


def _whitener_word(x1: int, source: list[int]) -> int:
    """Replay one 0x144074 call: each set bit b of (2*x1+3) XORs source[7-b]."""
    mask = ((x1 << 1) + 3) & _MASK16
    value = 0
    for bit in range(8):
        if (mask >> bit) & 1:
            value ^= source[7 - bit]
    return value & _MASK16


def _d0_source(d4: list[int]) -> list[int]:
    """The eight d4 halfwords consumed by the d0 source-word selector."""
    d4_bytes = b"".join(word.to_bytes(4, "big") for word in d4)
    return [int.from_bytes(d4_bytes[i:i + 2], "little") for i in range(16, 32, 2)]


def _selector_halfword(mask: int, source: list[int]) -> int:
    """XOR source words selected by one 8-bit d0 selector mask."""
    value = 0
    for bit in range(8):
        if (mask >> bit) & 1:
            value ^= source[7 - bit]
    return value & _MASK16


def _d0_words(d4: list[int], head=None) -> list[int]:
    """Descriptor #0: 36 big-endian words, including the separate W0/X prefix.

    The GENUINE device phases (HEAD_FIRST / HEAD_RESIGN) are short selector
    prefixes followed by the stable halfword cycle; they are dispatched through
    the generic `head + cycle` path and reproduce every genuine capture.  The
    longer SYNTH_* tables reproduce only the synthetic fill_runs corpus and are
    routed separately so verify_d0.py keeps working.  Callers minting a live
    request must pass a genuine head (default HEAD_FIRST).
    """
    source = _d0_source(d4)
    real_head = HEAD_FIRST if head is None else head

    if real_head == SYNTH_HEAD_FIRST:
        selectors = _D0_SELECTORS_FIRST + tuple(0x40 | (i & 7) for i in range(12, 72))
    elif real_head == SYNTH_HEAD_RESIGN:
        selectors = _D0_SELECTORS_RESIGN + tuple(0x40 | (i & 7) for i in range(13, 72))
    elif real_head == SYNTH_HEAD_RESIGN_ALT:
        selectors = _D0_SELECTORS_RESIGN_ALT + tuple(0x40 | (i & 7) for i in range(14, 72))
    else:
        # Genuine phases and any explicit custom head: prefix selectors, then
        # the stable cycle resumes at the first index after the prefix.
        selectors = tuple(real_head[i] if i < len(real_head) else (0x40 | (i & 7))
                          for i in range(72))

    values = [_selector_halfword((selector << 1) + 3, source)
              for selector in selectors]
    raw = b"".join(value.to_bytes(2, "little") for value in values)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 144, 4)]


def region(V: int, pid: int, tid: int = 0, head=None):
    """Return ``(d0, d2, d4)`` as descriptor words for the given fill instant.

    V   : tv_sec ^ tv_usec at the fill instant (< 2**32)
    pid : process id; only the low 16 bits reach the native seed
    tid : accepted for the contract, provably unused on this path
    head: per-request d0 phase (see _d0_words); None -> HEAD_FIRST.
    """
    del tid  # verified absent from the d0/d2 materializer and the d4 path
    seed = ((V & _MASK32) ^ ((pid & _MASK16) << 16)) & _MASK32
    d4 = _d4_words(seed)
    d0 = _d0_words(d4, head=head)
    # d2 is the little-endian store of the seed, read back as a BE word.
    d2 = int.from_bytes(seed.to_bytes(4, "little"), "big")
    return d0, d2, d4


if __name__ == "__main__":
    for v in (0x6AA21400, 0x6AA21401, 0x6AA21402, 0x6AA21403,
              0x6AA215E4, 0x6AAC93A0):
        d0, d2, d4 = region(v, 12345, 12346)
        print(hex(v), [f"{x:08x}" for x in d0[:6]], f"{d2:08x}",
              [f"{x:08x}" for x in d4])
