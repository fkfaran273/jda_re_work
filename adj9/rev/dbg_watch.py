"""dbg_watch.py - watch writes into the builder ctx block: who writes the
descriptor cells (ctx+0x70 + i*16), the junk cell ctx+0x540, and the poll
haystack buffers ctx+0x808/0x818.  Also log every cell fetch at 0x8d118.
Usage: python dbg_watch.py
"""
import os
import sys
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dbg_replay as D
from unicorn import *
from unicorn.arm64_const import *

CTX = 0x300000FF2D8          # deterministic (twice-run verdict)
CTX_SZ = 0x878
JUNK = 0x0EB03378F1B88779


class WatchEmu(D.DbgEmu):
    def __init__(self, cfg=None):
        super().__init__(cfg)
        self.writes = []       # (pc, addr, size, value)
        self.fetches = []      # (i50, x5) at 0x8d118
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self.hook_wr,
                         begin=CTX, end=CTX + CTX_SZ - 1)
        self.mu.hook_add(UC_HOOK_CODE, self.hook_fetch, begin=0x8D118, end=0x8D118)

    def hook_wr(self, uc, access, address, size, value, ud):
        if len(self.writes) < 5000:
            self.writes.append((uc.reg_read(UC_ARM64_REG_PC), address, size, value))

    def hook_fetch(self, uc, address, size, ud):
        i50 = struct.unpack("<Q", uc.mem_read(uc.reg_read(UC_ARM64_REG_SP) + 0x50, 8))[0]
        x5 = uc.reg_read(UC_ARM64_REG_X5)
        self.fetches.append((i50, x5))


def main():
    e = WatchEmu()
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    print("stopped=%s" % st)

    print("\n=== cell fetches at 0x8d118 (i50 -> ptr) ===")
    for i50, x5 in e.fetches:
        tag = ""
        if x5 == JUNK:
            tag = "  <== JUNK"
        print("  i50=0x%-4x ptr=0x%x%s" % (i50, x5, tag))

    print("\n=== writes into poll cells (ctx+0x2d0/0x310/0x330/0x370/0x540) ===")
    for off in (0x2d0, 0x2d8, 0x310, 0x318, 0x330, 0x338, 0x370, 0x378,
                0x540, 0x548, 0x560, 0x5b0, 0x5f0):
        rows = [(pc, sz, v) for pc, a, sz, v in e.writes if a == CTX + off]
        print("  ctx+0x%03x: %d writes" % (off, len(rows)))
        for pc, sz, v in rows[:8]:
            print("     pc=0x%-7x size=%d val=0x%x" % (pc, sz, v))

    print("\n=== writes into haystack area ctx+0x800..0x878 ===")
    rows = [(pc, a, sz, v) for pc, a, sz, v in e.writes if 0x800 <= a - CTX < 0x878]
    print("  total: %d" % len(rows))
    for pc, a, sz, v in rows[:40]:
        print("     pc=0x%-7x ctx+0x%03x size=%d val=0x%x" % (pc, a - CTX, sz, v))

    print("\n=== all writes with value == JUNK ===")
    n = 0
    for pc, a, sz, v in e.writes:
        if v == JUNK or (sz == 4 and v in (0xF1B88779, 0x0EB03378)):
            print("     pc=0x%-7x ctx+0x%03x size=%d val=0x%x" % (pc, a - CTX, sz, v))
            n += 1
            if n > 30:
                break

    print("\n=== first 60 ctx writes overall (chronological) ===")
    for pc, a, sz, v in e.writes[:60]:
        print("     pc=0x%-7x ctx+0x%03x size=%d val=0x%x" % (pc, a - CTX, sz, v))


if __name__ == "__main__":
    main()
