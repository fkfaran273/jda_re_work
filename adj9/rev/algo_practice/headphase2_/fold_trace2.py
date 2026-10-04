"""fold_trace2.py -- every fold with its exact output address + buffer dump."""
import os, sys, struct, json
from collections import defaultdict

REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR
import emu_8d6f4 as E
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_X11, UC_ARM64_REG_W4,
                                 UC_ARM64_REG_LR)

POST = 0x1441ac   # instruction right after `strh w4, [x11]` in 0x144074


def run(urandom_hex="11223344", n=0):
    cfg = FR.build_cfg(n)
    cfg["urandom8"] = bytes.fromhex(urandom_hex)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    folds = []
    seen = set()

    def h(uc, address, size, ud):
        ctx = uc.reg_read(UC_ARM64_REG_X0)
        sel = uc.reg_read(UC_ARM64_REG_X1) & 0xFF
        x11 = uc.reg_read(UC_ARM64_REG_X11)
        w4 = uc.reg_read(UC_ARM64_REG_W4) & 0xFFFF
        folds.append((hex(uc.reg_read(UC_ARM64_REG_LR)), sel, x11, w4))
        seen.add(ctx)
    mu.hook_add(UC_HOOK_CODE, h, begin=POST, end=POST)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    ctx = sorted(seen)[0]
    try:
        buf = bytes(mu.mem_read(ctx, 0x120))
    except Exception:
        buf = b""
    blob = e.result.get("blob") or b""
    return {"stopped": st, "folds": folds, "ctx": ctx, "buf": buf.hex(),
            "blob16": blob[:16].hex()}, e


if __name__ == "__main__":
    ur = sys.argv[1] if len(sys.argv) > 1 else "11223344"
    log, e = run(ur)
    print("stopped", log["stopped"], "folds", len(log["folds"]), "ctx", hex(log["ctx"]))
    print("last 24 folds (lr, sel, dst-ctx, value):")
    for lr, sel, x11, w4 in log["folds"][-24:]:
        print("   %-10s sel=%02x  dst=ctx+%#x  val=%04x" % (lr, sel, x11 - log["ctx"], w4))
    print("ctx+0x00..0x120:", log["buf"])
    print("distinct dst offsets:", sorted(set(x11 - log["ctx"] for _, _, x11, _ in log["folds"])))
