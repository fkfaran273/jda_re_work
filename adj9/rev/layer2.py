"""adj9 layer-2 primitive — Python port of libsigner.so's string/buffer decryptor.

Native source (all state machines resolved, see WALL_A_SLICE_3.md §6):

  0x13dfd0  park_miller_step(state*)        : x = (16807*x) mod 2^31-1, Schrage
  0x143c88  shuffle16(buf16*, rng)          : 16 Fisher-Yates swaps, buf[i]<->buf[r%(i+1)]
  0x143b20  search_slot(ctx*)               : first i in 0..71 with
                                              ctx_word[0x18+i] == ctx_word[0x60+(i&7)],
                                              else 72    (ctx = base of a 0xd0+ region;
                                              word idx rel. to ctx+0x30 region start)
  0x144074  fold16(ctx*, len)               : seed=search_slot(ctx)
                                              cursor = ctx + seed*2 + 0x30 (writeback +0x30)
                                              mask = (2*len + 3) & 0xffff
                                              for x9 in 0..15:
                                                  if mask>>x9 & 1:
                                                      src = ctx_word[(15-x9) + 8]
                                                          # x19 = ctx + (15-x9+1)*2 + 0x10
                                                      acc = src ^ acc
                                                      *cursor = acc
                                                      nxt_key = src
                                                  acc = nxt_key   (0x1441cc: w2=w3)
                                              (writes hit ONE 16-bit slot per call)
  0x1441e4  decrypt_word(ctx*, len)        : fold16(ctx, len); returns via 143b20 search

Ctx layout (from the seal + string callers):
  ctx+0x00 : w1 stored by caller (id/tag)
  ctx+0x08 : Park-Miller state (int64)
  ctx+0x10..0x30 : 16-byte source words region (shuffled by 143c88 at init)
  ctx+0x30..0xc0 : 72-word state region (search domain; also fold writeback +0x30)
  ctx+0xc0..0xd0 : 8-word match table
"""
import struct

M31 = (1 << 31) - 1

def park_miller_step(state):
    """x = (16807 * x) mod (2^31-1), Schrage; state 0 -> 0x75bd924-ish default seed.
    Native: q=127773 (0x1f31d), r=2836 (0xb14), a=16807 (0x41a7)."""
    x = state if state != 0 else 0x075bd924 & 0x7fffffff
    # note: native default w9 = 0x075bd924 (mov w9,#0xd924; movk w9,#0x75b,16)
    hi, lo = divmod(x, 127773)
    x = 16807 * lo - 2836 * hi
    if x < 0:
        x += M31
    x &= 0x7fffffff if x <= M31 else 0xffffffff  # and w0,w9,#0x7fffffff
    return x & M31 if (x & M31) != 0 or x == M31 else x

def park_miller(x):
    hi, lo = divmod(x, 127773)
    v = 16807 * lo - 2836 * hi
    if v < 0:
        v += M31
    return v

def shuffle16(buf, rng_state):
    """143c88: for i in 0..15 (x25 = x8 running, n = x25+1):
         r = rng(); j = r % n; swap(buf[i], buf[j])
       Loop control: x8 counts down from 0x10? (cmp x8,#0x10; csel) — modelled as
       16 rounds, n = i+1 growing (add x26, x25, #1)."""
    out = bytearray(buf)
    x25 = 0
    for _ in range(16):
        n = x25 + 1
        # native draws ONE rng value, uses r%n as swap index, and x8 = r/n feeds loop?
        # (udiv w8,w0,w26; msub w10) — x8=r/n only used for the cmp x8,#0x10 exit test
        r = park_miller(rng_state[0]); rng_state[0] = r
        j = r % n
        out[x25], out[j] = out[j], out[x25]
        x25 += 1
        if r // n == 0x10:
            break
    return bytes(out)

def search_slot(ctx):
    """143b20: find first i in 0..71 with ctx_word[i] == table[i&7]; else 72.
    ctx is a bytearray; words are little-endian u16.
    ctx+0x30..0xc0 = words[0x18..0x60] rel to ctx+0 — i.e. word index 24..95.
    table at ctx+0xc0 = word index 96..103."""
    words = struct.unpack_from('<%dH' % (len(ctx) // 2), ctx)
    for i in range(72):
        if words[24 + i] == words[96 + (i & 7)]:
            return i
    return 72

def fold16(ctx, length, seed=None):
    """144074: XOR-fold selected words into the slot at search index.
    Returns the new ctx (bytes) and the slot word index written."""
    if seed is None:
        seed = search_slot(ctx)
    b = bytearray(ctx)
    words = lambda: struct.unpack_from('<%dH' % (len(b) // 2), b)
    mask = (2 * length + 3) & 0xffff
    acc = 0
    abs_cursor = 24 + seed
    struct.pack_into('<H', b, abs_cursor * 2, 0)   # 0x144114 strh wzr,[x11,#0x30]!
    for x9 in range(16):
        if (mask >> x9) & 1:
            # CORRECTED (was `8 + (15-x9) + 1`, off by one word):
            # 0x144124 add x19,x0,x7,lsl#1 ; 0x144130 add x19,x19,#0x10
            #   x7 = 15-i  ->  byte 0x10 + 2*(15-i) = 0x2E - 2i  ->  word 23-i
            src_abs = 8 + (15 - x9)
            w = struct.unpack_from('<H', b, src_abs * 2)[0]
            acc = w ^ acc                      # 0x14419c eor w4,w4,w2
            struct.pack_into('<H', b, abs_cursor * 2, acc & 0xffff)
            # CORRECTED: acc keeps the chained value (native: w2 = w3 = w4).
        # else: acc unchanged
    return bytes(b)

def decrypt_stream(ctx, lengths):
    """Apply the primitive for a sequence of (len) values as the callers do."""
    out = bytearray(ctx)
    for ln in lengths:
        out = bytearray(fold16(bytes(out), ln))
    return bytes(out)

if __name__ == '__main__':
    # quick sanity on raw .data bytes (string-table base 0x151c20 as ctx)
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from elf import ELF
    from decryptors import LIB
    e = ELF(LIB)
    ctx = bytearray(e.read(0x151c20, 0xd0))
    print("ctx head:", ctx[:32].hex())
    print("words[0..16]:", [hex(w) for w in struct.unpack_from('<16H', ctx)])
    print("search_slot:", search_slot(ctx))
