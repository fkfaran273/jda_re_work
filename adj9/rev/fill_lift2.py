"""fill_lift2.py - deeper instrumentation of the fold/whiten engine.
1. full reg-dump instruction trace of [0x143000,0x144220) (the engine window)
2. all memory writes into the descriptor area 0x300000ffd00..0x300000ffe00
3. x0/x1/x26 at the copy site (source buffer of the 16 raw units)
Writes fill_runs/lift2_<tag>.json (+ prints the engine size / key regs).
"""
import json, sys, time
sys.path.insert(0, ".")
import emu_8d6f4 as E
from unicorn import *
from unicorn.arm64_const import *

ENG_LO, ENG_HI = 0x143000, 0x144220
DESC_LO, DESC_HI = 0x300000ffd00, 0x300000ffe00
REGS = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
        UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11,
        UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15,
        UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19,
        UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
        UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
        UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30, UC_ARM64_REG_SP]

def run(tag, cfg):
    e = E.Emu(cfg=cfg)
    icount = [0]
    trace = []
    def eng(uc, address, size, ud):
        icount[0] += 1
        trace.append((icount[0], address,
                      [uc.reg_read(r) for r in REGS]))
    e.mu.hook_add(UC_HOOK_CODE, eng, begin=ENG_LO, end=ENG_HI)
    writes = []
    def wr(uc, access, address, size, value, ud):
        if DESC_LO <= address < DESC_HI:
            writes.append((icount[0], uc.reg_read(UC_ARM64_REG_PC),
                           address, size, value))
    e.mu.hook_add(UC_HOOK_MEM_WRITE, wr)
    t0 = time.time()
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    dt = time.time() - t0
    # final buffers
    lens = {0x300000ffd20: 4, 0x300000ffd30: 32, 0x300000ffd50: 144}
    by = {b: bytes(e.mu.mem_read(b, n)) for b, n in lens.items()}
    # compress the trace: keep pc + the regs that change vs previous line
    out = {"tag": tag, "cfg": cfg, "stopped": st, "engine_insns": len(trace),
           "desc_writes": writes,
           "buf2": by[0x300000ffd20].hex(), "buf4": by[0x300000ffd30].hex(),
           "buf0": by[0x300000ffd50].hex(),
           "trace": trace, "dt": dt}
    json.dump(out, open("fill_runs/lift2_%s.json" % tag, "w"))
    print(tag, st, "engine insns", len(trace), "desc writes", len(writes),
          "%.1fs" % dt, flush=True)
    if trace:
        first = trace[0]
        print("  first engine pc 0x%x x0=0x%x x1=0x%x" %
              (first[1], first[2][0], first[2][1]))

if __name__ == "__main__":
    tag = sys.argv[1] if len(sys.argv) > 1 else "V0"
    cfg = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    run(tag, cfg)
