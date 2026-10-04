"""adj9 — the 32-bit seed model (WALL_A_SLICE_4.md §1).

The fold's ONLY randomness is a single 32-bit value read from /dev/urandom.
This module models exactly that path, so the offline decoder becomes a
<=2^31 seed search + forward simulation instead of a cryptanalytic problem.

Verified native chain (libsigner.so, md5 dbe36c643d174f1cca240dcec1f4c585):

  0x13e0e4  get8random(out8)   openat(AT_FDCWD,"/dev/urandom",O_CLOEXEC)
                               read(fd,out8,8)  close(fd)      <- 8 bytes
  0x143794  wrapper(ctx)       get8random(sp); ldr w1,[sp]     <- LOW 32 BITS ONLY
                               ctx_init(ctx, w1)
  0x1437ec  ctx_init(ctx,seed) ctx[0]=seed; LCG_init(ctx+8,seed);
                               shuffle16(scratch16, ctx+8)
  0x13e030  LCG_init(p,seed)   *(u64*)p = seed
  0x13dfd0  lcg_step(p)        x = 16807*x mod (2^31-1)  (Schrage q=127773 r=2836)
  0x143c88  shuffle16(buf,st)  zero buf; 16 rounds of
                               r=lcg(st); j=r%(i+1); buf[i]=buf[j]; buf[j]=i

CONFIRMED: the seed's provenance, size (32 bit), the LCG, the call graph
(0x143794's only caller is 0xdb160 inside nSign; 0x13e0e4's only caller is
0x1437b8).

NOT YET CONFIRMED (needs the live ctx dump, see WALL_A_SLICE_4.md §6/§7):
how shuffle16's 16-byte output is laid into ctx+0x10..0x30, and the initial
content of the key-state region ctx+0x30..0xd0. Those are parameters here.
"""
import struct

M31 = (1 << 31) - 1
A, Q, R = 16807, 127773, 2836
DEFAULT_SEED = 0x075BD924


def lcg_step(state):
    """0x13dfd0 — Park-Miller minimal standard, Schrage form. Returns (new_state, out31)."""
    x = state if state != 0 else DEFAULT_SEED
    hi, lo = divmod(x, Q)
    x = A * lo - R * hi
    if x < 0:
        x += M31
    return x, (x & 0x7FFFFFFF)


def lcg_draws(seed, n):
    """First n outputs for a given 32-bit seed (the native state is the seed)."""
    st = seed & 0xFFFFFFFF
    out = []
    for _ in range(n):
        st, v = lcg_step(st)
        out.append(v)
    return out


def shuffle16(seed):
    """0x143c88 — 16 rounds, buf starts zeroed, buf[i]=buf[j] then buf[j]=i."""
    st = seed & 0xFFFFFFFF
    buf = bytearray(16)
    for i in range(16):
        st, r = lcg_step(st)
        j = r % (i + 1)
        buf[i] = buf[j]
        buf[j] = i & 0xFF
    return bytes(buf), st


def ctx_from_seed(seed, key_state=None, table=None):
    """Build a ctx image per the verified chain.

    ctx+0x00  u32 seed        (0x14384c: str w1,[x9],#0x10)
    ctx+0x08  u64 LCG state   (0x13e030: str x11,[x0])
    ctx+0x10  16 B shuffle16 output
    ctx+0x30  72-word key-state region  (content = caller/claims; unknown yet)
    ctx+0xc0  8-word match table
    """
    ctx = bytearray(0xD0)
    struct.pack_into('<I', ctx, 0x00, seed & 0xFFFFFFFF)
    struct.pack_into('<Q', ctx, 0x08, seed & 0xFFFFFFFF)
    shuf, _ = shuffle16(seed)
    ctx[0x10:0x20] = shuf
    if key_state is not None:
        ctx[0x30:0xC0] = bytes(key_state)[:0x90]
    if table is not None:
        ctx[0xC0:0xD0] = bytes(table)[:0x10]
    return bytes(ctx)


def fold16(ctx, length, seed=None):
    """0x144074 — XOR-fold into the slot located by 0x143b20's search.
    Source words are read from the REVERSED 16-word region at ctx+0x10..0x30.
    Writes hit exactly ONE 16-bit slot in the ctx+0x30 region."""
    b = bytearray(ctx)
    if seed is None:
        seed = search_slot(b)
    mask = (2 * length + 3) & 0xFFFF
    abs_cursor = 24 + seed          # +0x30 region, word index
    acc = 0
    for x9 in range(16):
        if (mask >> x9) & 1:
            w = struct.unpack_from('<H', b, (8 + (15 - x9) + 1) * 2)[0]
            acc = w ^ acc
            struct.pack_into('<H', b, abs_cursor * 2, acc & 0xFFFF)
            acc = w
    return bytes(b)


def search_slot(ctx):
    """0x143b20 — first i in 0..71 with word[0x18+i] == word[0x60+(i&7)], else 72."""
    words = struct.unpack_from('<%dH' % (len(ctx) // 2), ctx)
    for i in range(72):
        if words[24 + i] == words[96 + (i & 7)]:
            return i
    return 72


def seed_space_report():
    print("seed = 32 bits from /dev/urandom, only low 32 used (ldr w1,[sp])")
    print("Park-Miller modulus = 2^31-1 -> state space <= 2^31-1")
    print("=> offline decode = forward-simulate <= 2^31 candidates, not cryptanalysis")


if __name__ == '__main__':
    seed_space_report()
    s = 0xDEADBEEF
    print("\nseed 0x%08x draws[:6] = %s" % (s, [hex(v) for v in lcg_draws(s, 6)]))
    sh, st = shuffle16(s)
    print("shuffle16 ->", sh.hex(), " state after =", hex(st))
    ctx = ctx_from_seed(s)
    print("ctx head:", ctx[:0x20].hex())
    print("search_slot(ctx) =", search_slot(ctx))
    print("fold16(ctx, 42)[0x30:0x50] =", fold16(ctx, 42)[0x30:0x50].hex())
