"""slotmap.py -- per-slot selector map of the native d0 region.

Hook 0x14407c (just after `lsl w10, w1, #1` in 0x144074): there
    x0 = ctx, w10 = (sel << 1), x2 = destination slot index,
and the store target is ctx + slot*2 + 0x30 with the folded value in w4 at
0x1441ac.  This covers EVERY caller, including the 72-fold loop at 0x143a3c.
"""
import os, sys, struct, json
from collections import defaultdict

REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR
import emu_8d6f4 as E
import adj9_pure as AP
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X2, UC_ARM64_REG_W10,
                                 UC_ARM64_REG_X11, UC_ARM64_REG_W4,
                                 UC_ARM64_REG_LR)

ENTRY = 0x14407c
POST = 0x1441ac


def run(urandom_hex="11223344", n=0):
    cfg = FR.build_cfg(n)
    cfg["urandom8"] = bytes.fromhex(urandom_hex)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    cur = {}
    folds = []

    def h_in(uc, a, s, ud):
        cur["ctx"] = uc.reg_read(UC_ARM64_REG_X0)
        cur["sel"] = (uc.reg_read(UC_ARM64_REG_W10) & 0xFFFFFFFF) >> 1
        cur["idx"] = uc.reg_read(UC_ARM64_REG_X2)

    def h_out(uc, a, s, ud):
        folds.append(dict(lr=hex(uc.reg_read(UC_ARM64_REG_LR)), sel=cur.get("sel"),
                          idx=cur.get("idx"), ctx=cur.get("ctx"),
                          dst=uc.reg_read(UC_ARM64_REG_X11),
                          val=uc.reg_read(UC_ARM64_REG_W4) & 0xFFFF))
    mu.hook_add(UC_HOOK_CODE, h_in, begin=ENTRY, end=ENTRY)
    mu.hook_add(UC_HOOK_CODE, h_out, begin=POST, end=POST)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    ctx = min(f["dst"] for f in folds) - 0x30
    buf = bytes(mu.mem_read(ctx, 0x140))
    return {"stopped": st, "folds": folds, "ctx": ctx, "buf": buf}, e


def main():
    for ur in ["11223344", "deadbeef", "a5a5a5a5", "00000001"]:
        log, e = run(ur)
        ctx, buf = log["ctx"], log["buf"]
        print("=" * 72)
        print("urandom8=%s ctx=%#x folds=%d" % (ur, ctx, len(log["folds"])))
        print("  ctx+0x00:", buf[0:16].hex(" "))
        d0 = buf[0x30:0x30 + 144]
        print("  d0[0:16] (native, LE-stored):", d0[0:16].hex(" "))
        first = {}
        for f in log["folds"]:
            off = f["dst"] - ctx
            if 0x30 <= off < 0x30 + 144 and off not in first:
                first[off] = f
        seq = [first[o] for o in sorted(first)]
        print("  slots filled: %d" % len(seq))
        print("   sels :", " ".join("%02x" % f["sel"] for f in seq))
        print("   lrs  :", " ".join(f["lr"][2:] for f in seq))
        print("   vals :", " ".join("%04x" % f["val"] for f in seq))
        # seed search: find seed S with head16_for(S, phase) == native head bytes
        # native stores each halfword little-endian; head16_for emits big-endian
        # so the record's head bytes == byteswap of the native d0[0:16] halves
        native_head = b"".join(d0[2 * j:2 * j + 2][::-1] for j in range(8))
        print("  native head after per-halfword byte swap:", native_head.hex(" "))
        cands = {"urandom_be": int(ur, 16), "urandom_le": int.from_bytes(bytes.fromhex(ur), "little"),
                 "ctx+8_be": int.from_bytes(buf[8:12], "big"),
                 "ctx+8_le": int.from_bytes(buf[8:12], "little")}
        for name, S in cands.items():
            for ph in [(0x2B,), (0x2B, 0x48)]:
                if AP.head16_for(S, ph) == native_head:
                    print("  *** MATCH head16_for(%s=%08x, %s)" %
                          (name, S, [hex(x) for x in ph]))
            raw = AP.head16_for(S)
            if raw == d0[0:16]:
                print("  *** MATCH raw head16_for(%s=%08x) == native d0[0:16]" % (name, S))


if __name__ == "__main__":
    main()
