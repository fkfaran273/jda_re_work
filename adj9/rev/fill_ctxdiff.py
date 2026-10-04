import json, struct, sys
sys.path.insert(0, ".")
import emu_8d6f4 as E
from unicorn import *
from unicorn.arm64_const import *

def run_ctx(cfg):
    e = E.Emu(cfg=cfg)
    box = {}
    def serhook(uc, address, size, ud):
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        if x2 == 11 and "ctx" not in box:
            # builder ctx is the last ctx_seen[2]
            if e.ctx_seen:
                box["ctx"] = bytes(uc.mem_read(e.ctx_seen[-1][2], 0x878))
            # also snapshot the descriptor #0 buffer
            box["t"] = 1
    e.mu.hook_add(UC_HOOK_CODE, serhook, begin=0x12D39C, end=0x12D39C)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    return box.get("ctx"), e

a, ea = run_ctx({})
b, eb = run_ctx({"sec": 1789240513, "usec": 499999})
wa = struct.unpack("<%dI" % (len(a)//4), a)
wb = struct.unpack("<%dI" % (len(b)//4), b)
diffs = [(i*4, wa[i], wb[i]) for i in range(len(wa)) if wa[i] != wb[i]]
print("ctx diffs base vs Tsame: %d words" % len(diffs))
for off, x, y in diffs:
    print("  +0x%03x: %08x -> %08x" % (off, x, y))
