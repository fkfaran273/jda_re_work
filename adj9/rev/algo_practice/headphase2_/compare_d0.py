"""compare_d0.py -- native d0 buffer vs the Python model, and the selector list.

For each pinned urandom8:
  * run the VM, dump ctx+0x00..0x20 (the ctx header) and ctx+0x30..0xbf (d0, 144 B)
  * log every fold with its selector (read at 0x1441f4) and its dst (0x1441ac)
  * try to match head16_for(seed) against d0[0:16] for candidate seeds
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
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_X11, UC_ARM64_REG_W4,
                                 UC_ARM64_REG_LR)

SEL_ENTRY = 0x1441f4   # `mov w19, w1` -- w1 is the selector
POST = 0x1441ac        # just after `strh w4, [x11]` in 0x144074


def run(urandom_hex="11223344", n=0):
    cfg = FR.build_cfg(n)
    cfg["urandom8"] = bytes.fromhex(urandom_hex)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    cur = {"sel": None, "ctx": None}
    folds = []

    def h_sel(uc, address, size, ud):
        cur["sel"] = uc.reg_read(UC_ARM64_REG_X1) & 0xFF
        cur["ctx"] = uc.reg_read(UC_ARM64_REG_X0)

    def h_post(uc, address, size, ud):
        folds.append((hex(uc.reg_read(UC_ARM64_REG_LR)), cur["sel"],
                      uc.reg_read(UC_ARM64_REG_X11), uc.reg_read(UC_ARM64_REG_W4) & 0xFFFF))
    mu.hook_add(UC_HOOK_CODE, h_sel, begin=SEL_ENTRY, end=SEL_ENTRY)
    mu.hook_add(UC_HOOK_CODE, h_post, begin=POST, end=POST)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    ctx = folds[0][2] & ~0xFFFFFFFFFFFF
    # derive ctx robustly: use the dst addresses
    ctx = min(f[2] for f in folds) & ~0x1FF
    ctx = folds[0][2] - 0x30
    buf = bytes(mu.mem_read(ctx, 0x140))
    return {"stopped": st, "folds": folds, "ctx": ctx, "buf": buf}, e


def main():
    for ur in ["11223344", "deadbeef", "a5a5a5a5"]:
        log, e = run(ur)
        buf = log["buf"]
        ctx = log["ctx"]
        print("=" * 70)
        print("urandom8=%s ctx=%#x" % (ur, ctx))
        print("  ctx+0x00:", buf[0:16].hex(" "))
        print("  ctx+0x10:", buf[0x10:0x30].hex(" "))
        d0 = buf[0x30:0x30 + 144]
        print("  d0[0:32] :", d0[0:32].hex(" "))
        print("  head(native d0[0:16]) =", d0[0:16].hex(" "))
        # folds that write into d0
        infolds = [(lr, s, x11 - ctx, v) for lr, s, x11, v in log["folds"]
                   if 0x30 <= x11 - ctx < 0x30 + 144]
        # first write to each slot
        first = {}
        for lr, s, off, v in infolds:
            if off not in first:
                first[off] = (lr, s, v)
        print("  distinct folds writing d0: %d" % len(first))
        seq = [first[o] for o in sorted(first)]
        print("   offsets:", " ".join(str(o) for o in sorted(first))[:400])
        print("   sels   :", " ".join("%02x" % s for _, s, _ in seq))
        print("   lrs    :", " ".join(lr[2:] for lr, _, _ in seq))
        print("   vals   :", " ".join("%04x" % v for _, _, v in seq))
        # match a seed
        for cand in [int(ur, 16), int.from_bytes(buf[0:4], "big"),
                     int.from_bytes(buf[8:12], "big"),
                     int.from_bytes(buf[0:4], "little"),
                     int.from_bytes(buf[8:12], "little")]:
            h = AP.head16_for(cand)
            if h == d0[0:16]:
                print("  *** head16_for(%08x) MATCHES native d0[0:16]" % cand)
        for ph in [(0x2B,), (0x2B, 0x48), (0x2B, 0x34)]:
            for cand in [int(ur, 16), int.from_bytes(buf[8:12], "big"),
                         int.from_bytes(buf[8:12], "little")]:
                if AP.head16_for(cand, ph) == d0[0:16]:
                    print("  *** head16_for(%08x, %s) MATCHES" % (cand, [hex(x) for x in ph]))


if __name__ == "__main__":
    main()
