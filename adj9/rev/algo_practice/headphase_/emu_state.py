"""emu_state.py - log every read/write of the walk-state globals
(0x1559c0-0x155c00) during a full signing, with pc, value, and order.
usage: python emu_state.py [ROW] [urandom8_hex]
"""
import os, struct, sys, json

HERE = os.path.dirname(os.path.abspath(__file__))
REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR
import emu_8d6f4 as E
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_LR

SITES = {0x8c48: 0x2b, 0x973a8: 0x30, 0xde08: 0x34, 0xe38c: 0x37, 0xee58: 0x38,
         0x1555c: 0x3b, 0x152b4: 0x35, 0x152e8: 0x36, 0x14df4: 0x2d,
         0xfaa0: 0x5, 0x1b550: 0x48, 0xf620: 0x7, 0x14fa8: 0x22, 0x14e7c: 0x2e}


def run(n=0, urandom8=None):
    cfg = FR.build_cfg(n)
    if urandom8:
        cfg["urandom8"] = bytes.fromhex(urandom8)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    ev = []

    def hw(uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        ev.append(("W", hex(pc), hex(address), size,
                   hex(value & ((1 << (8 * size)) - 1))))
    mu.hook_add(UC_HOOK_MEM_WRITE, hw, begin=0x1559c0, end=0x155c00)

    def hr(uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        ev.append(("R", hex(pc), hex(address), size, None))
    mu.hook_add(UC_HOOK_MEM_READ, hr, begin=0x1559c0, end=0x155c00)

    for site in SITES:
        def mk(s):
            def h(uc, address, size, ud):
                ev.append(("FOLD", hex(s), None, 0, None))
            return h
        mu.hook_add(UC_HOOK_CODE, mk(site), begin=site, end=site)

    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    blob = e.result.get("blob") or b""
    return {"events": ev, "stopped": st, "blob": blob.hex()}, e


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    ur = sys.argv[2] if len(sys.argv) > 2 else None
    log, e = run(n, ur)
    json.dump(log, open(os.path.join(HERE, "state_%d_%s.json" % (n, ur or "emu")), "w"))
    ev = log["events"]
    print("stopped:", log["stopped"], "events:", len(ev))
    for row in ev:
        print("  %s pc=%s addr=%s sz=%d val=%s" % row)
