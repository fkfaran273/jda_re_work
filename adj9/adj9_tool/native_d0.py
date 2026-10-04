"""Native (Unicorn) producer for the adj9 descriptor region.

Runs the real phase-1 materializer (0x1437ec) from libsigner.so under an
ARM64 emulator and reads back the seed-derived region:

    ctx+0x00   seed (32-bit)
    ctx+0x10   d4   (16 little-endian halfwords)
    ctx+0x30   d0   (72 little-endian halfwords == 36 big-endian words)

Phase 1 executes the full 72-call ordinary whitener pass (verified by trace:
72 entries to 0x144074 with x1 = 0x40|(i&7), initial = i).  The body does not
consume d4 independently -- d4 is folded into d0 -- so d0 here is the value
the server recomputes and checks.
"""

import os
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_PROT_ALL
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_TPIDR_EL0,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_W1,
)

_HERE = os.path.dirname(os.path.abspath(__file__))
_SO = os.path.join(_HERE, "..", "..", "extracted", "arm64", "lib", "arm64-v8a", "libsigner.so")

ENTRY = 0x1437ec
MAP_SIZE = 0x160000
STACK = 0x70000000
TLS = 0x71000000
CTX = 0x72000000
LR_SENT = 0x73000000

_d = open(os.path.normpath(_SO), "rb").read()


def _bswap32(x):
    x &= 0xFFFFFFFF
    return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x >> 8) & 0xFF00) | ((x >> 24) & 0xFF)


def region_native(seed: int):
    """Return ``(d0, d2, d4)`` descriptor words for one signing, from the
    native phase-1 materializer.  d0/d2/d4 match the shapes that
    adj9_signer.region() returns, so they drop straight into the body builder.
    """
    seed &= 0xFFFFFFFF
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mu.mem_map(0x0, MAP_SIZE, UC_PROT_ALL)
    mu.mem_write(0x0, _d[:MAP_SIZE])
    mu.mem_map(STACK, 0x20000)
    mu.mem_map(TLS, 0x2000)
    mu.mem_write(TLS + 0x28, struct.pack("<Q", 0x1122334455667788))  # stable stack canary
    mu.mem_map(CTX, 0x4000)
    mu.mem_write(CTX, b"\x00" * 0x4000)
    mu.mem_map(LR_SENT, 0x1000)

    mu.reg_write(UC_ARM64_REG_LR, LR_SENT)
    mu.reg_write(UC_ARM64_REG_SP, STACK + 0x18000)
    mu.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
    mu.reg_write(UC_ARM64_REG_X0, CTX)
    mu.reg_write(UC_ARM64_REG_W1, seed)

    mu.emu_start(ENTRY, LR_SENT, count=5_000_000)
    ctx = bytes(mu.mem_read(CTX, 0x4000))

    d4_hw = struct.unpack("<16H", ctx[0x10:0x30])                       # native d4 halfwords
    d0_hw = struct.unpack("<72H", ctx[0x30:0x30 + 144])                # native d0 halfwords

    def pack(halfwords):
        # Match adj9_signer._d0_words / _d4_words packing exactly: each halfword
        # is written little-endian, then every 4 bytes (two halfwords) is read
        # big-endian into one descriptor word.  The server recomputes these words,
        # so the packing must match the body builder's convention byte-for-byte.
        raw = b"".join(h.to_bytes(2, "little") for h in halfwords)
        return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, len(raw), 4)]

    d4 = pack(d4_hw)
    d0 = pack(d0_hw)
    d2 = _bswap32(seed)
    return d0, d2, d4


# ---------------------------------------------------------------------------
# POST-HEAD d0 -- the value the server actually checks.
#
# The body descriptor #0 is NOT the phase-1 (ordinary) d0 above.  During the
# live signing VM (0xda668 -> H -> F) a sequence of "head" calls runs through
# the tail wrapper 0x1441e4 -> selector 0x143b20 -> whitener 0x144074.  The
# selector is a bump allocator: each call overwrites the next unmodified
# prefix slot of d0 with value(seed, w1).  The result is the POST-HEAD d0 =
# ordinary d0 with prefix slots 0..N-1 replaced (tail unchanged), where N is
# the head-call count.  The head sequence is a PURE FUNCTION OF THE SEED
# (independent of claims), but its exact values are produced by the live VM --
# they cannot be derived in Python, and the Python _d0_words head model does
# NOT reproduce them.  So we drive the full native nSign and read back the
# final ctx+0x30 at the signer return.
# ---------------------------------------------------------------------------

_SIGNER_RET = 0xDB1C4       # post-head d0 lives in ctx+0x30 at this return
_PHASE1_RET = 0x1437C8      # x19 = ctx, right after ctx_init (captures base)


def _add_rev_to_path():
    rev = os.path.normpath(os.path.join(_HERE, "..", "rev"))
    if rev not in sys.path:
        sys.path.insert(0, rev)
    return rev


def posthead_region_native(seed: int, sec: int = 1789240512, props=None,
                           strvals=None):
    """Return ``(d0, d2, d4)`` for one signing using the POST-HEAD d0.

    Runs the real libsigner.so signing path (``nSign``) under Unicorn with a
    fixed seed, and captures the final post-head d0 (ctx+0x30) at the signer
    return.  d2 = bswap32(seed) as always; d4 is the seed-derived descriptor-4
    material (captured from the same ctx at 0x1437c8).  d0 is claims-
    independent, so the harness's own dummy claims do not affect it.

    `props`/`strvals` let a caller pass device props / claim values; they do
    not change d0 but are accepted so the harness config is explicit.
    """
    import sys as _sys
    _add_rev_to_path()
    import emu_8d6f4 as E
    from unicorn import UC_HOOK_CODE as _HC

    seed &= 0xFFFFFFFF
    cfg = dict(E.DEF_CFG)
    cfg["urandom8"] = seed.to_bytes(4, "little") + b"\x11\x22\x33\x44"
    cfg["sec"] = int(sec)
    cfg["time_sec"] = int(sec)
    cfg["usec"] = 500000
    if props is not None:
        cfg["props"] = dict(props)
    if strvals is not None:
        cfg["strvals"] = dict(strvals)

    e = E.Emu(cfg)
    mu = e.mu
    cap = {"ctx": None, "d0": None, "d4": None}

    def _snap(addr, n):
        return [struct.unpack_from("<H", bytes(mu.mem_read(addr, 2 * n)), 2 * i)[0]
                for i in range(n)]

    def h_pm(uc, addr, size, ud):
        ctx = uc.reg_read(UC_ARM64_REG_X19)
        cap["ctx"] = ctx
        try:
            cap["d4"] = _snap(ctx + 0x10, 16)          # d4 at ctx+0x10
        except Exception:
            pass

    def h_ret(uc, addr, size, ud):
        c = cap.get("ctx")
        if c is not None and cap.get("d0") is None:
            try:
                cap["d0"] = _snap(c + 0x30, 72)         # post-head d0 at ctx+0x30
            except Exception:
                pass

    mu.hook_add(_HC, h_pm, begin=_PHASE1_RET, end=_PHASE1_RET)
    mu.hook_add(_HC, h_ret, begin=_SIGNER_RET, end=_SIGNER_RET)

    e.run(0xDB1CC, count=400_000_000, argstyle="nsign")

    if cap.get("d0") is None or cap.get("d4") is None:
        raise RuntimeError(
            "post-head capture failed (d0=%s d4=%s) for seed %#x; stopped=%s"
            % ("ok" if cap.get("d0") else "MISSING",
               "ok" if cap.get("d4") else "MISSING", seed, e.result.get("stopped")))

    def pack(halfwords):
        raw = b"".join(h.to_bytes(2, "little") for h in halfwords)
        return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, len(raw), 4)]

    d0 = pack(cap["d0"])
    d4 = pack(cap["d4"])
    d2 = _bswap32(seed)
    return d0, d2, d4


if __name__ == "__main__":
    for s in (0x11223344, 0xDEADBEEF, 1):
        d0, d2, d4 = region_native(s)
        print("seed %#x  d2=%#010x  d4=%s" % (s, d2, " ".join("%08x" % x for x in d4)))
        print("        d0[:6]=%s" % (" ".join("%08x" % x for x in d0[:6])))
