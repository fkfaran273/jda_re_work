"""compare_runs.py -- pinned vs default urandom: what really writes d0 slots 0..9.

Also answers whether the ten immediate-bearing handlers ever touch d0 at all.
"""
import os, sys, struct

REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR
import emu_8d6f4 as E
import adj9_pure as AP
import adj9_signature as SG
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X2, UC_ARM64_REG_W10,
                                 UC_ARM64_REG_X11, UC_ARM64_REG_W4, UC_ARM64_REG_LR)

ENTRY = 0x14407c
POST = 0x1441ac


def run(urandom_hex=None):
    cfg = FR.build_cfg(0)
    if urandom_hex:
        cfg["urandom8"] = bytes.fromhex(urandom_hex)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    cur = {}
    folds = []

    def h_in(uc, a, s, ud):
        cur["sel"] = (uc.reg_read(UC_ARM64_REG_W10) & 0xFFFFFFFF) >> 1
        cur["ctx"] = uc.reg_read(UC_ARM64_REG_X0)

    def h_out(uc, a, s, ud):
        folds.append((uc.reg_read(UC_ARM64_REG_LR), cur.get("sel"),
                      uc.reg_read(UC_ARM64_REG_X11), uc.reg_read(UC_ARM64_REG_W4) & 0xFFFF))
    mu.hook_add(UC_HOOK_CODE, h_in, begin=ENTRY, end=ENTRY)
    mu.hook_add(UC_HOOK_CODE, h_out, begin=POST, end=POST)
    e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    blob = bytes(e.result["blob"])
    ctx = min(f[2] for f in folds) - 0x30
    buf = bytes(mu.mem_read(ctx, 0x200))
    rec = SG.whiten_body_inverse(blob[16:160], blob[:16])
    return {"folds": folds, "ctx": ctx, "buf": buf, "rec": rec, "blob": blob}


def report(tag, ur):
    r = run(ur)
    ctx = r["ctx"]
    rec = r["rec"]
    print("=" * 72)
    print("%s  urandom=%s" % (tag, ur))
    print("  blob[:32]  = %s" % r["blob"][:32].hex())
    print("  genuine[0] = %s" % FR.SIGNINGS[0]["blob"][:32])
    print("  seed(rec[20:24] BE) = %08x" % struct.unpack_from(">I", rec, 20)[0])
    print("  rec head    = %s" % bytes(rec[3:19]).hex(" "))
    print("  d0[0:16]    = %s" % r["buf"][0x30:0x40].hex(" "))
    # folds that touch d0 slots 0..9  (dst - ctx - 0x30 == 2*slot)
    hits = []
    for lr, sel, dst, val in r["folds"]:
        off = dst - ctx - 0x30
        if 0 <= off < 20:
            hits.append((hex(lr), sel, off // 2, val))
    print("  folds writing d0 slots 0..9: %d" % len(hits))
    for h in hits:
        print("     lr=%-9s sel=%02x slot=%d val=%04x" % h)


if __name__ == "__main__":
    report("PINNED", "11223344")
    report("DEFAULT(unpinned)", None)
