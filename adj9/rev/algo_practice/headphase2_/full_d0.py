"""full_d0.py -- confirm the ENTIRE 144-byte native d0 against adj9_pure.region,
and confirm the slot<->selector map is input-independent.
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

ENTRY, POST = 0x14407c, 0x1441ac
PH8 = (0x30, 0x2B, 0x34, 0x37, 0x38, 0x3B, 0x35, 0x36)
PH10 = PH8 + (0x2D, 0x05)


def run(ur, over=None):
    cfg = FR.build_cfg(0)
    cfg["urandom8"] = bytes.fromhex(ur)
    if over:
        cfg.update(over)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    cur, folds = {}, []

    def h_in(uc, a, s, ud):
        cur["sel"] = (uc.reg_read(UC_ARM64_REG_W10) & 0xFFFFFFFF) >> 1

    def h_out(uc, a, s, ud):
        folds.append((uc.reg_read(UC_ARM64_REG_LR), cur.get("sel"),
                      uc.reg_read(UC_ARM64_REG_X11), uc.reg_read(UC_ARM64_REG_W4) & 0xFFFF))
    mu.hook_add(UC_HOOK_CODE, h_in, begin=ENTRY, end=ENTRY)
    mu.hook_add(UC_HOOK_CODE, h_out, begin=POST, end=POST)
    e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    ctx = min(f[2] for f in folds) - 0x30
    buf = bytes(mu.mem_read(ctx, 0x200))
    blob = bytes(e.result["blob"])
    rec = SG.whiten_body_inverse(blob[16:160], blob[:16])
    return folds, ctx, buf, rec, blob


def d0_bytes(seed, head):
    """Rebuild the native 144-byte d0 payload from adj9_pure primitives."""
    src = AP._transpose16(AP._shuffled_halfwords(seed))[8:16]
    sels = [head[a] if a < len(head) else (0x40 | (a & 7)) for a in range(72)]
    return b"".join(AP._fold_selector((s << 1) + 3, src).to_bytes(2, "little")
                    for s in sels)


def main():
    variants = [
        ("base", "11223344", None),
        ("deadbeef", "deadbeef", None),
        ("other-package", "0a0b0c0d", {"package": "com.other.app"}),
        ("other-pid", "11223344", {"pid": 4242, "tid": 4243}),
        ("other-props", "55556666", {"props": dict(FR.MOTO_G42_PROPS, **{"ro.product.model": "ZZ"})}),
    ]
    for nm, ur, over in variants:
        folds, ctx, buf, rec, blob = run(ur, over)
        seed = int.from_bytes(bytes.fromhex(ur), "little")
        d0_native = buf[0x30:0x30 + 144]
        d0_model = d0_bytes(seed, PH10)
        d0_model8 = d0_bytes(seed, PH8)
        # slot -> selector actually used (last write)
        last = {}
        for lr, sel, dst, val in folds:
            off = dst - ctx - 0x30
            if 0 <= off < 20:
                last[off // 2] = sel
        smap = [last.get(j) for j in range(10)]
        print("%-14s pin=%s seed=%08x" % (nm, ur, seed))
        print("   slot->sel (last write, slots 0..9): %s" %
              " ".join("--" if s is None else "%02x" % s for s in smap))
        print("   d0[0:20] native = %s" % d0_native[:20].hex(" "))
        print("   d0[0:20] PH10   = %s   %s" % (d0_model[:20].hex(" "),
                                               "MATCH" if d0_model[:20] == d0_native[:20] else "no"))
        print("   d0[0:20] PH8    = %s   %s" % (d0_model8[:20].hex(" "),
                                               "MATCH" if d0_model8[:20] == d0_native[:20] else "no"))
        print("   FULL 144 B PH10 = %s" % ("MATCH" if d0_model == d0_native else "differs"))
        print("   rec head        = %s" % bytes(rec[3:19]).hex(" "))
        print("   head16_for(PH8) = %s" % AP.head16_for(seed, PH8).hex(" "))


if __name__ == "__main__":
    main()
