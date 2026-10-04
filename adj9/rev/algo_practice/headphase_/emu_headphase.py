"""emu_headphase.py - watch the d0 head-phase machinery live in a full signing.

Hooks:
  * mem writes to 0x155228 (2-byte head-phase global) and 0x155e5c (flag)
  * 0x144fd4  flag clear
  * 0x145070  XOR-0x46 decode block
  * 0x144fdc  generator call site (log x0/x1/x2)
  * 0x1441e4  apply_one entry (x1 = selector byte, x2 = slot index)
  * 0x144074  write_selector (w1 = selector, w2 = index)
  * 0x144214  fold driver entry (x0 = d0 base, x1 = selector array, x2 = count)
"""
import os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
import full_replay as FR
import emu_8d6f4 as E
from unicorn import UC_HOOK_MEM_WRITE, UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                 UC_ARM64_REG_PC, UC_ARM64_REG_LR)

PHASE_G, FLAG_G = 0x155228, 0x155e5c


def run(n=0):
    cfg = FR.build_cfg(n)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    log = []

    def hook_w(uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        if address == PHASE_G:
            log.append(("W-PHASE", hex(pc), hex(lr), hex(value & 0xFF),
                        hex(value & 0xFFFF)))
        elif FLAG_G <= address <= FLAG_G + 1:
            log.append(("W-FLAG", hex(pc), hex(lr), hex(value & 0xFF)))

    mu.hook_add(UC_HOOK_MEM_WRITE, hook_w, begin=PHASE_G, end=PHASE_G)
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_w, begin=FLAG_G, end=FLAG_G + 1)

    def at(pc_, name, fmt):
        def h(uc, address, size, ud):
            args = {r: uc.reg_read(reg) for r, reg in fmt.items()}
            log.append((name, hex(pc_),
                        {k: hex(v) for k, v in args.items()}))
        mu.hook_add(UC_HOOK_CODE, h, begin=pc_, end=pc_)

    at(0x144fd4, "FLAG-CLEAR", {})
    at(0x145070, "XOR-BLOCK", {})
    at(0x144fdc, "GEN-CALL", {0: UC_ARM64_REG_X0, 1: UC_ARM64_REG_X1,
                              2: UC_ARM64_REG_X2})
    at(0x1441e4, "APPLY1", {1: UC_ARM64_REG_X1, 2: UC_ARM64_REG_X2})
    at(0x144074, "WR-SEL", {1: UC_ARM64_REG_X1, 2: UC_ARM64_REG_X2})
    at(0x144214, "FOLD", {0: UC_ARM64_REG_X0, 1: UC_ARM64_REG_X1,
                          2: UC_ARM64_REG_X2})
    at(0x143a38, "FILL-CALL", {0: UC_ARM64_REG_X0, 1: UC_ARM64_REG_X1,
                               2: UC_ARM64_REG_X2})

    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    blob = e.result.get("blob") or b""
    print("stopped=%s blob_len=%d" % (st, len(blob)))
    print("phase global final:", bytes(mu.mem_read(PHASE_G, 2)).hex())
    print("flag:", bytes(mu.mem_read(FLAG_G, 2)).hex())
    return log, blob


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    log, blob = run(n)
    import json
    json.dump({"log": log, "blob": blob.hex()},
              open(os.path.join(HERE, "hp_trace_%d.json" % n), "w"))
    for row in log[:80]:
        print(row)
    print("...")
    for row in log[-40:]:
        print(row)
    print("total events", len(log))
