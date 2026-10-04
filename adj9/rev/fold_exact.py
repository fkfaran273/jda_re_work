#!/usr/bin/env python3
"""adj9 — EXACT port of the native fold machinery, read straight off the disassembly.

Corrects/confirms `layer2.py` (which hedged: "modelled as", "not yet exact").
Every line below is derived from the raw ARM64 in
`extracted/arm64/lib/arm64-v8a/libsigner.so`. Addresses in comments.

FUNCTIONS
---------
0x13dfd0  park_miller(state*)      -> 31-bit value, Schrage minimal-standard LCG
0x143c88  shuffle16(buf16*, rng)   -> ascending Fisher-Yates; buf becomes a perm of 0..15
0x143b20  search_slot(ctx*)        -> first i in 0..71 with  u16(ctx+0x30+2i) == u16(ctx+0xc0+2*(i&7))
0x144074  fold16(ctx*, len, slot)  -> ONE 16-bit write:  u16(ctx+0x30+2*slot) = XOR_{i in setbits(mask)} u16(ctx+0x10+2*(15-i))
0x1441e4  fold_word(ctx*, len)     -> search_slot(ctx) then fold16(ctx, len, slot)
0x144214  driver(ctx*, words*, n)  -> for i in 0..n-1: fold_word(ctx, words[i])
0x143794  ctx_wrapper(ctx*)        -> seed = get8random()[0:4]; ctx_init(ctx, seed)
0x1437ec  ctx_init(ctx*, seed)     -> ctx[0]=seed; LCG state @ ctx+8; builds ctx[0x10..0x30]
                                      from a 16-byte shuffle permutation; snapshots
                                      ctx[0x30..0x40] into ctx[0xC0..0xD0]

WHY IT IS A "SNOWBALL"
----------------------
fold16 writes into the very region (ctx+0x30..0xc0) that search_slot scans, and the
snapshot table at 0xc0 is a frozen copy of the *original* words 0..7. So each write
invalidates one match candidate and changes the slot the next call lands on. That is
the whole "cipher": no key, no S-box — just a self-modifying XOR fold.

KEY CORRECTION vs layer2.py
---------------------------
layer2.py read the fold source at byte 0x30-2i; the native reads 0x2E-2i
(word 23-i, not 24-i) — see 0x144124/0x144130. It also did not zero the target
word first (0x144114). Both are fixed here.
"""
import struct

M31 = (1 << 31) - 1


# ---------------------------------------------------------------- 0x13dfd0
def park_miller(state):
    """x = (16807*x) mod (2^31-1), Schrage. Native default when state==0 is
    0x075bd924 (mov w9,#0xd924; movk w9,#0x75b,lsl#16)."""
    x = state if state != 0 else 0x075BD924
    h, lo = divmod(x, 127773)          # q = 0x1f31d
    v = 16807 * lo - 2836 * h          # a = 0x41a7, r = 0xb14
    if v < 0:
        v += M31
    return v & 0x7FFFFFFF, v           # (returned 31-bit, stored state)


# ---------------------------------------------------------------- 0x143c88
def shuffle16(rng):
    """Ascending Fisher-Yates over a zeroed 16-byte buffer.
    buf[j] = i is written (not buf[i]) => the result is a permutation of 0..15."""
    buf = bytearray(16)
    for i in range(16):
        r, _ = rng()
        j = r % (i + 1)
        buf[i], buf[j] = buf[j], i
    return bytes(buf)


# ---------------------------------------------------------------- 0x143b20
def search_slot(ctx):
    for i in range(72):
        if u16(ctx, 0x30 + 2 * i) == u16(ctx, 0xC0 + 2 * (i & 7)):
            return i
    return 72


# ---------------------------------------------------------------- 0x144074
def fold16(ctx, length, slot):
    """XOR-fold 16 words into a single slot. Returns the value written."""
    mask = (2 * length + 3) & 0xFFFF
    p = 0x30 + 2 * slot
    u16_put(ctx, p, 0)                       # 0x144114  strh wzr,[x11,#0x30]!
    acc = 0                                  # w2 initialised to w3 = 0 (0x1441cc)
    for i in range(16):
        if (mask >> i) & 1:
            src = u16(ctx, 0x10 + 2 * (15 - i))   # 0x144124/0x144130
            acc = src ^ acc                       # 0x14419c
            u16_put(ctx, p, acc)                  # 0x1441a4
        # else: acc unchanged
    return u16(ctx, p)


# ---------------------------------------------------------------- 0x1441e4
def fold_word(ctx, length):
    return fold16(ctx, length, search_slot(ctx))


# ---------------------------------------------------------------- 0x144214
def driver(ctx, words):
    """words = the record's 16-bit little-endian words (each used as `len`)."""
    for w in words:
        fold_word(ctx, w)


# ---------------------------------------------------------------- helpers
def u16(b, off):
    return struct.unpack_from('<H', b, off)[0]


def u16_put(b, off, v):
    struct.pack_into('<H', b, off, v & 0xFFFF)


# ---------------------------------------------------------------- 0x143794/0x1437ec
def ctx_init(ctx, seed, rng_factory=None):
    """Reconstruction of the two ctx fields we can read with certainty:
      ctx[0x00] = seed (32-bit)
      ctx[0x08] = Park-Miller state = seed
      ctx[0x10..0x30] = 16 words assembled from the shuffle16 permutation
      ctx[0xc0..0xd0] = snapshot copy of ctx[0x30..0x40]   (0x143b0c..0x143b10)
    The *source* value that feeds the 16-word build (w23 in the native) is the
    record-dependent part that is still unresolved."""
    struct.pack_into('<I', ctx, 0x00, seed & 0xFFFFFFFF)
    struct.pack_into('<Q', ctx, 0x08, seed & M31)       # LCG state
    state = [seed & M31]
    def rng():
        r, s = park_miller(state[0]); state[0] = s
        return r, s
    perm = shuffle16(rng)
    # NOTE: ctx[0x10..0x30] is built by 0x1439c4..0x143a24 as
    #   w8 = 1 << (15 - perm[i]);  w8 = (w8 - 1) | (w8 & src_bits);  strh w8,[ctx+0x10+2i]
    # where `src_bits` (w23, either the low or high 16 bits per a flag) is the
    # record-dependent value NOT yet resolved. Left untouched on purpose.
    ctx[0xC0:0xD0] = ctx[0x30:0x40]    # frozen match table (0x143b0c..0x143b10)
    return perm


if __name__ == '__main__':
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    LIB = r'C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so'
    try:
        from elf import ELF
        e = ELF(LIB)
        ctx = bytearray(e.read(0x151c20, 0xD0))
        print('static .data ctx head :', ctx[:32].hex())
        print('search_slot(static)   :', search_slot(ctx))
    except Exception as ex:
        print('static demo skipped:', ex)
    # self-test: permutation property of shuffle16
    st = [123456789]
    def rng():
        r, s = park_miller(st[0]); st[0] = s
        return r, s
    p = shuffle16(rng)
    print('shuffle16 perm        :', list(p), 'is_perm=', sorted(p) == list(range(16)))
