"""emu_headphase2.py - deeper: log every write_selector strh target+value,
the pass-2 buffer base (x0 at 0x1441e4), the caller LR, the generator writes,
and the final d0 buffer vs the pure model.
"""
import os, struct, sys, json

HERE = os.path.dirname(os.path.abspath(__file__))
REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
import full_replay as FR
import emu_8d6f4 as E
from unicorn import UC_HOOK_MEM_WRITE, UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_X2, UC_ARM64_REG_LR,
                                 UC_ARM64_REG_PC)

PHASE_G = 0x155228


def run(n=0):
    cfg = FR.build_cfg(n)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    log = []

    def hw(uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        log.append(("W", hex(pc), hex(address), size, hex(value & 0xFFFF)))

    # catch writes into the .data tail (phase/schedule) and the d0 work buffer
    mu.hook_add(UC_HOOK_MEM_WRITE, hw, begin=0x154000, end=0x157000)
    mu.hook_add(UC_HOOK_MEM_WRITE, hw, begin=0x3000000000, end=0x4000000000)

    def at(pc_, name, regs):
        def h(uc, address, size, ud):
            vals = {r: hex(uc.reg_read(reg)) for r, reg in regs.items()}
            vals["lr"] = hex(uc.reg_read(UC_ARM64_REG_LR))
            log.append((name, hex(pc_), vals))
        mu.hook_add(UC_HOOK_CODE, h, begin=pc_, end=pc_)

    at(0x1441e4, "APPLY1", {0: UC_ARM64_REG_X0, 1: UC_ARM64_REG_X1})
    at(0x144fdc, "GEN-CALL", {0: UC_ARM64_REG_X0, 1: UC_ARM64_REG_X1,
                              2: UC_ARM64_REG_X2})
    at(0x145650, "GEN-ENTRY", {0: UC_ARM64_REG_X0, 1: UC_ARM64_REG_X1,
                               2: UC_ARM64_REG_X2})

    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    blob = e.result.get("blob") or b""
    print("stopped=%s blob_len=%d" % (st, len(blob)))
    return log, blob, e, mu


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    log, blob, e, mu = run(n)
    json.dump({"log": log, "blob": blob.hex()},
              open(os.path.join(HERE, "hp2_trace_%d.json" % n), "w"))
    # summarize
    print("total events:", len(log))
    for row in log:
        if row[0] in ("GEN-CALL", "GEN-ENTRY", "APPLY1"):
            print(row)
    print("-- writes into 0x1552xx --")
    for row in log:
        if row[0] == "W" and row[2].startswith("0x155"):
            print(row)
    print("-- rand seed --", e.rand_calls[:4])
