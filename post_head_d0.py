"""Reproduce Adjust libsigner POST-HEAD d0 (the d0 actually consumed by the signer).

Mechanism (verified by disassembly + Unicorn trace):
  * phase-1 0x1437ec(ctx, seed) fills ctx+0x30 with a repeating 8-halfword (4-word) pattern
    and copies ctx+0x30..0x3f -> ctx+0xc0..0xcf (the "free-slot template").
  * every live head write  BL 0x1441e4(ctx, w1)  -> selector 0x143b20 (bump-allocator:
    finds first slot k where ctx+0x30+k == ctx+0xc0+(k&7), i.e. still "free")
    -> whitener 0x144074 writes value(seed,w1) at ctx+0x30+k.
  * therefore: post-head d0 = phase-1 d0 whose PREFIX slots 0..N-1 are replaced, in live
    execution order, by value(seed, w1_0..w1_{N-1}).  The tail (slots N..) is unchanged.
  * value(seed, w1) is computed by running the REAL selector+whitener on the phase-1 buffer.

d0 = ctx+0x30, 72 halfwords (36 words).  ctx+0xc0 is working template, not part of d0.

Usage:
  from post_head_d0 import apply_seq, d0_half, d0_words
  ctx = apply_seq(seed, [0x1,0x2,0x3,0x1e,0x1f])   # field-index sequence (live order)
  print(d0_half(ctx))   # 72 halfwords
  print(d0_words(ctx))  # 36 words
"""
import struct
from unicorn import *
from unicorn.arm64_const import *

SO = "extracted/arm64/lib/arm64-v8a/libsigner.so"
_d = open(SO, "rb").read()
MAP_SIZE = 0x160000
STACK, TLS, CTX, LR = 0x70000000, 0x71000000, 0x72000000, 0x73000000
PHASE1, TAIL = 0x1437ec, 0x1441e4

def _mu():
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mu.mem_map(0, MAP_SIZE, UC_PROT_ALL); mu.mem_write(0, _d[:MAP_SIZE])
    mu.mem_map(STACK, 0x20000); mu.mem_map(TLS, 0x2000)
    mu.mem_write(TLS + 0x28, struct.pack("<Q", 0x1122334455667788))
    mu.mem_map(CTX, 0x4000); mu.mem_write(CTX, b"\x00" * 0x4000); mu.mem_map(LR, 0x1000)
    mu.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
    return mu

def phase1_ctx(seed):
    mu = _mu()
    mu.reg_write(UC_ARM64_REG_LR, LR); mu.reg_write(UC_ARM64_REG_SP, STACK + 0x18000)
    mu.reg_write(UC_ARM64_REG_X0, CTX); mu.reg_write(UC_ARM64_REG_W1, seed & 0xffffffff)
    mu.emu_start(PHASE1, LR, count=50_000_000)
    return bytes(mu.mem_read(CTX, 0x4000))

def value(seed, w1):
    """value(seed,w1) = halfword the real selector+whitener write for field index w1."""
    mu = _mu(); mu.mem_write(CTX, phase1_ctx(seed))
    mu.reg_write(UC_ARM64_REG_LR, LR); mu.reg_write(UC_ARM64_REG_SP, STACK + 0x18000)
    mu.reg_write(UC_ARM64_REG_X0, CTX); mu.reg_write(UC_ARM64_REG_W1, w1 & 0xffff)
    mu.emu_start(TAIL, LR, count=1_000_000)
    return struct.unpack_from("<H", bytes(mu.mem_read(CTX, 0x4000)), 0x30)[0]

def apply_seq(seed, seq):
    """Apply head writes in live order on the evolving buffer (real code)."""
    ctx = bytearray(phase1_ctx(seed)); mu = _mu()
    for w1 in seq:
        mu.mem_write(CTX, bytes(ctx))
        mu.reg_write(UC_ARM64_REG_LR, LR); mu.reg_write(UC_ARM64_REG_SP, STACK + 0x18000)
        mu.reg_write(UC_ARM64_REG_X0, CTX); mu.reg_write(UC_ARM64_REG_W1, w1 & 0xffff)
        mu.emu_start(TAIL, LR, count=1_000_000)
        ctx = bytearray(mu.mem_read(CTX, 0x4000))
    return ctx

def d0_half(ctx, n=72): return [struct.unpack_from("<H", ctx, 0x30 + 2 * i)[0] for i in range(n)]
def d0_words(ctx, n=36):
    h = d0_half(ctx, 2 * n); return [h[2 * i] | (h[2 * i + 1] << 16) for i in range(n)]

if __name__ == "__main__":
    seed = 0x11223344
    seq = [0x1, 0x2, 0x3, 0x1e, 0x1f]  # H live head sequence (order fixed by the state machine)
    ctx = apply_seq(seed, seq)
    base = d0_half(phase1_ctx(seed)); fin = d0_half(ctx)
    print("post-head d0 (72 halfwords):")
    for r in range(0, 72, 12): print("  " + " ".join("%04x" % v for v in fin[r:r + 12]))
    print("changed vs phase-1:", [(i, "%04x" % base[i], "%04x" % fin[i]) for i in range(72) if base[i] != fin[i]])
    print("HALFWORDS=" + " ".join("%04x" % v for v in fin))
    print("WORDS=" + " ".join("%08x" % v for v in d0_words(ctx)))
