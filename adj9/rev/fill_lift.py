"""fill_lift.py - instrument the region fill: log every 16-bit store into the
region descriptor buffers (#2/#4/#0) plus the whitener keys, across V values.
Sites (from the watchpoint timeline): 0x143f68 copy-strh, 0x14419c eor(pre),
0x1441a4 whiten-strh(post), 0x144114 zero-strh."""
import json, struct, sys
sys.path.insert(0, ".")
import emu_8d6f4 as E
from unicorn import *
from unicorn.arm64_const import *

SITES = {0x143F68: "copy", 0x14419C: "pre", 0x1441A4: "post", 0x144114: "zero"}

def run_v(tag, cfg):
    e = E.Emu(cfg=cfg)
    icount = [0]
    def ichook(uc, address, size, ud):
        icount[0] += 1
    e.mu.hook_add(UC_HOOK_CODE, ichook)
    events = []
    def sh(uc, address, size, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        kind = SITES.get(pc, "?")
        if kind == "copy":
            val = uc.reg_read(UC_ARM64_REG_X27) & 0xFFFF
            dst = uc.reg_read(UC_ARM64_REG_X0) + (uc.reg_read(UC_ARM64_REG_X26) & 0xFFFFFFFF) * 2
            events.append((icount[0], kind, dst & 0xFFFFFFFFFFFF, val, 0))
        elif kind == "pre":
            val = uc.reg_read(UC_ARM64_REG_X4) & 0xFFFF
            key = uc.reg_read(UC_ARM64_REG_X2) & 0xFFFFFFFF
            events.append((icount[0], kind, uc.reg_read(UC_ARM64_REG_X11) & 0xFFFFFFFFFFFF, val, key))
        elif kind == "post":
            val = uc.reg_read(UC_ARM64_REG_X4) & 0xFFFF
            events.append((icount[0], kind, uc.reg_read(UC_ARM64_REG_X11) & 0xFFFFFFFFFFFF, val, 0))
        else:
            events.append((icount[0], kind, uc.reg_read(UC_ARM64_REG_X11) & 0xFFFFFFFFFFFF, 0, 0))
    for pc in SITES:
        e.mu.hook_add(UC_HOOK_CODE, sh, begin=pc, end=pc)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    lens = {0x300000ffd20: 4, 0x300000ffd30: 32, 0x300000ffd50: 144}
    by = {b: bytes(e.mu.mem_read(b, n)) for b, n in lens.items()}
    out = {"tag": tag, "cfg": cfg, "stopped": st, "events": events,
           "buf2": by[0x300000ffd20].hex(), "buf4": by[0x300000ffd30].hex(),
           "buf0": by[0x300000ffd50].hex(), "n_events": len(events)}
    json.dump(out, open("fill_runs/lift_%s.json" % tag, "w"))
    print(tag, st, "events", len(events), "#0[:12]", by[0x300000ffd50][:12].hex(), flush=True)

if __name__ == "__main__":
    for d in (0, 1, 2, 3, 100, 100000):
        run_v("V%+d" % d, {"usec": 500000 + d} if d else {})
    run_v("pidtid", {"pid": 12346, "tid": 12347})
