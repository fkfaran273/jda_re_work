"""phase.py -- exact second-round fold map + head snapshot ordering.

Traces, in order:
  * every fold (sel, dst, val) at 0x14407c/0x1441ac
  * the 16-byte head snapshot `str q0, [x9,#0xc0]` at 0x143b10..0x143b14
and dumps ctx+0x30 (d0) and ctx+0xc0 (head) at the end.
"""
import os, sys, struct, json

REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR
import emu_8d6f4 as E
import adj9_pure as AP
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X2, UC_ARM64_REG_W10,
                                 UC_ARM64_REG_X11, UC_ARM64_REG_W4, UC_ARM64_REG_LR,
                                 UC_ARM64_REG_PC)

ENTRY = 0x14407c
POST = 0x1441ac
SNAP = 0x143b14        # `str q0, [x9, #0xc0]!` -- head = d0[0:16] -> ctx+0xc0


def run(urandom_hex="11223344", n=0, verbose=True):
    cfg = FR.build_cfg(n)
    cfg["urandom8"] = bytes.fromhex(urandom_hex)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    cur = {}
    ev = []

    def h_in(uc, a, s, ud):
        cur["sel"] = (uc.reg_read(UC_ARM64_REG_W10) & 0xFFFFFFFF) >> 1
        cur["ctx"] = uc.reg_read(UC_ARM64_REG_X0)

    def h_out(uc, a, s, ud):
        ev.append(("fold", uc.reg_read(UC_ARM64_REG_LR), cur.get("sel"),
                   uc.reg_read(UC_ARM64_REG_X11), uc.reg_read(UC_ARM64_REG_W4) & 0xFFFF))

    def h_snap(uc, a, s, ud):
        ctx = min(x[3] for x in ev) - 0x30
        ev.append(("snap", None, None, ctx + 0xc0,
                   bytes(mu.mem_read(ctx + 0xc0, 16)).hex()))
    mu.hook_add(UC_HOOK_CODE, h_in, begin=ENTRY, end=ENTRY)
    mu.hook_add(UC_HOOK_CODE, h_out, begin=POST, end=POST)
    mu.hook_add(UC_HOOK_CODE, h_snap, begin=SNAP, end=SNAP)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    ctx = min(x[3] for x in ev if x[0] == "fold") - 0x30
    buf = bytes(mu.mem_read(ctx, 0x200))
    return {"stopped": st, "ev": ev, "ctx": ctx, "buf": buf}, e


def main():
    for ur in ["11223344", "deadbeef"]:
        log, e = run(ur)
        ev, ctx, buf = log["ev"], log["ctx"], log["buf"]
        print("=" * 72)
        print("urandom8=%s ctx=%#x events=%d" % (ur, ctx, len(ev)))
        # first 72 folds are the cycle; everything after is the phase pass
        tail = [x for x in ev if x[0] == "fold"][72:]
        snaps = [x for x in ev if x[0] == "snap"]
        print("  snapshots of ctx+0xc0: %d" % len(snaps))
        for i, s in enumerate(snaps):
            print("    snap#%d @ctx+0xc0 = %s" % (i, s[4]))
        print("  post-cycle folds (%d), in order:" % len(tail))
        for k, (kind, lr, sel, dst, val) in enumerate(tail):
            print("    #%2d lr=%-9s sel=%s  slot=%3d  val=%04x" %
                  (k, hex(lr) if isinstance(lr, int) else lr,
                   "%02x" % sel if sel is not None else "?",
                   dst - ctx - 0x30, val))
        print("  ctx+0x30 (d0[0:32]) :", buf[0x30:0x50].hex(" "))
        print("  ctx+0xc0 (head)      :", buf[0xc0:0xd0].hex(" "))
        print("  ctx+0x90 (d0[0x20]) :", buf[0x90:0xb0].hex(" "))
        print("  ctx+0x20..0x30       :", buf[0x20:0x30].hex(" "))


if __name__ == "__main__":
    main()
