"""dbg_order.py - chronological interleaving of ctx writes and 0x8d118 cell
fetches; who writes cell 0x4d (ctx+0x540) and when relative to the scan.
"""
import os
import sys
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dbg_replay as D
from unicorn import *
from unicorn.arm64_const import *

CTX = 0x300000FF2D8
JUNK = 0x0EB03378F1B88779


class OrdEmu(D.DbgEmu):
    def __init__(self, cfg=None):
        super().__init__(cfg)
        self.ev = []            # chronological events
        self.nfetch = 0
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self.hook_wr,
                         begin=CTX, end=CTX + 0x878 - 1)
        self.mu.hook_add(UC_HOOK_CODE, self.hook_f, begin=0x8D118, end=0x8D118)
        self.mu.hook_add(UC_HOOK_CODE, self.hook_p, begin=0x8D364, end=0x8D364)

    def hook_wr(self, uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        self.ev.append(("W", pc, address - CTX, size, value))

    def hook_f(self, uc, address, size, ud):
        self.nfetch += 1
        i50 = struct.unpack("<Q", uc.mem_read(uc.reg_read(UC_ARM64_REG_SP) + 0x50, 8))[0]
        self.ev.append(("F", i50, self.nfetch))

    def hook_p(self, uc, address, size, ud):
        x8 = uc.reg_read(UC_ARM64_REG_X8)
        self.ev.append(("P", x8))


def main():
    e = OrdEmu()
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    print("stopped=%s  events=%d fetches=%d" % (st, len(e.ev), e.nfetch))

    # locate key events
    i_w2d0 = i_w310 = i_w330 = i_w370 = i_w540 = i_f1 = i_p1 = None
    for k, ev in enumerate(e.ev):
        if ev[0] == "W" and ev[2] == 0x2d0 and i_w2d0 is None: i_w2d0 = k
        if ev[0] == "W" and ev[2] == 0x310 and i_w310 is None: i_w310 = k
        if ev[0] == "W" and ev[2] == 0x330 and i_w330 is None: i_w330 = k
        if ev[0] == "W" and ev[2] == 0x370 and i_w370 is None: i_w370 = k
        if ev[0] == "W" and ev[2] == 0x540 and i_w540 is None: i_w540 = k
        if ev[0] == "F" and i_f1 is None: i_f1 = k
        if ev[0] == "P" and i_p1 is None: i_p1 = k
    print("first W cell0x26(0x2d0)=%s W cell0x2a(0x310)=%s W cell0x2c(0x330)=%s "
          "W cell0x30(0x370)=%s W junk(0x540)=%s F#1=%s P#1=%s"
          % (i_w2d0, i_w310, i_w330, i_w370, i_w540, i_f1, i_p1))

    print("\n--- events around the junk write (idx %s) ---" % i_w540)
    lo = max(0, (i_w540 or 0) - 12)
    for k in range(lo, min(len(e.ev), (i_w540 or 0) + 13)):
        ev = e.ev[k]
        if ev[0] == "W":
            print("  #%5d W pc=0x%-6x ctx+0x%03x sz=%d val=0x%x" % (k, ev[1], ev[2], ev[3], ev[4]))
        elif ev[0] == "F":
            print("  #%5d F i50=0x%x (fetch#%d)" % (k, ev[1], ev[2]))
        else:
            print("  #%5d P poll x8=0x%x" % (k, ev[1]))

    print("\n--- all writes into cell area [0x70..0x560) chronologically ---")
    for k, ev in enumerate(e.ev):
        if ev[0] == "W" and 0x70 <= ev[2] < 0x560:
            print("  #%5d W pc=0x%-6x ctx+0x%03x sz=%d val=0x%x" % (k, ev[1], ev[2], ev[3], ev[4]))


if __name__ == "__main__":
    main()
