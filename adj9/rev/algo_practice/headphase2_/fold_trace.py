"""fold_trace.py -- ground truth for the selector fold.

0x144074(ctx, w1) computes  ctx[slot] = XOR of ctx[0x10 + 2*(15-k)] over bits k
of ((w1<<1)+3).  At its `ret` (0x1441e0) the emulator gives us:
    x0 = ctx, x1 = selector, x2 = slot index, w2 = folded value.
0x1441e4(ctx, sel) is the public wrapper (tail-calls 0x144074 after 0x143b20
supplies the slot index).

We log every single fold the VM performs, with its caller, so we can see the
actual selector sequence and the slot it writes.
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
                                 UC_ARM64_REG_X2, UC_ARM64_REG_W4,
                                 UC_ARM64_REG_LR, UC_ARM64_REG_PC)

RET = 0x1441e0


def run(urandom_hex="11223344", n=0):
    cfg = FR.build_cfg(n)
    cfg["urandom8"] = bytes.fromhex(urandom_hex)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    folds = []
    ctxs = set()

    def h(uc, address, size, ud):
        ctx = uc.reg_read(UC_ARM64_REG_X0)
        sel = uc.reg_read(UC_ARM64_REG_X1) & 0xFF
        idx = uc.reg_read(UC_ARM64_REG_X2)
        val = uc.reg_read(UC_ARM64_REG_W4) & 0xFFFF
        folds.append({"ctx": hex(ctx), "sel": hex(sel), "idx": idx,
                      "val": val,
                      "lr": hex(uc.reg_read(UC_ARM64_REG_LR))})
        ctxs.add(ctx)
    mu.hook_add(UC_HOOK_CODE, h, begin=RET, end=RET)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    blob = e.result.get("blob") or b""
    return {"stopped": st, "folds": folds, "ctxs": sorted(ctxs),
            "blob16": blob[:16].hex(), "bloblen": len(blob)}, e


if __name__ == "__main__":
    ur = sys.argv[1] if len(sys.argv) > 1 else "11223344"
    log, e = run(ur)
    print("stopped", log["stopped"], "folds", len(log["folds"]))
    print("ctxs:", log["ctxs"])
    byc = defaultdict(list)
    for f in log["folds"]:
        byc[f["ctx"]].append((f["lr"], int(f["sel"], 16), f["idx"], f["val"]))
    for c, lst in byc.items():
        print("ctx %s : %d folds" % (c, len(lst)))
        print("   sels:", " ".join("%02x" % s for _, s, _, _ in lst))
        print("   idxs:", " ".join(str(i) for _, _, i, _ in lst[:120]))
        print("   vals:", " ".join("%04x" % v for _, _, _, v in lst[:120]))
        print("   lrs :", " ".join(l for l, _, _, _ in lst[:120]))
