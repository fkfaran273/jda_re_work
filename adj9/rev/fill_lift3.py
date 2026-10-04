"""fill_lift3.py - trace V's entry: extended engine window [0x13e000,0x144220),
write hooks over the descriptor stack area [0xffa00,0xffe00), gettimeofday log.
Two runs (base + usec+1) written to fill_runs/lift3_<tag>.json (trace compressed
to (gic, pc, 32 regs) but only for the extended engine window).
"""
import json, sys, time
sys.path.insert(0, ".")
import emu_8d6f4 as E
from unicorn import *
from unicorn.arm64_const import *

ENG_LO, ENG_HI = 0x13E000, 0x144220
ST_LO, ST_HI = 0x300000FFA00, 0x300000FFE00
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
    gic = [0]
    def tick(uc, address, size, ud):
        gic[0] += 1
    e.mu.hook_add(UC_HOOK_CODE, tick)
    trace = []
    def eng(uc, address, size, ud):
        trace.append((gic[0], address, [uc.reg_read(r) for r in REGS]))
    e.mu.hook_add(UC_HOOK_CODE, eng, begin=ENG_LO, end=ENG_HI)
    writes = []
    def wr(uc, access, address, size, value, ud):
        if ST_LO <= address < ST_HI:
            writes.append((gic[0], uc.reg_read(UC_ARM64_REG_PC),
                           address, size, value & (2**64-1)))
    e.mu.hook_add(UC_HOOK_MEM_WRITE, wr)
    gtod = []
    orig_plt = e.plt
    def plt2(nm, a, uc):
        r = orig_plt(nm, a, uc)
        if nm == "gettimeofday":
            gtod.append((gic[0], a, r))
        return r
    e.plt = plt2
    t0 = time.time()
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    dt = time.time() - t0
    lens = {0x300000ffd20: 4, 0x300000ffd30: 32, 0x300000ffd50: 144}
    by = {b: bytes(e.mu.mem_read(b, n)) for b, n in lens.items()}
    clocks = [c for c in e.calls if c[0] in ("gettimeofday", "time", "clock_gettime")]
    out = {"tag": tag, "cfg": cfg, "stopped": st, "dt": dt,
           "engine_insns": len(trace), "writes": writes, "gtod": gtod,
           "clocks_head": clocks[:6],
           "buf2": by[0x300000ffd20].hex(), "buf4": by[0x300000ffd30].hex(),
           "buf0": by[0x300000ffd50].hex(), "trace": trace}
    json.dump(out, open("fill_runs/lift3_%s.json" % tag, "w"))
    print(tag, st, "engine insns", len(trace), "writes", len(writes),
          "gtod", gtod, "%.1fs" % dt, flush=True)
    print("  buf2", by[0x300000ffd20].hex(), "buf4[:16]", by[0x300000ffd30][:16].hex())

if __name__ == "__main__":
    run("V0", {})
    run("V1", {"usec": 500001})
