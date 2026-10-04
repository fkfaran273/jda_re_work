"""dbg_x5.py - locate the instruction that first puts the junk marker
0xeb03378f1b88779 into x5 (which then becomes the poll pointer x1/x8), and
trace where the poll-phase pointers (x8 at 0x8d364) come from.
Usage: python dbg_x5.py
"""
import os
import sys
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dbg_replay as D
import emu_8d6f4 as E
from unicorn import *
from unicorn.arm64_const import *

JUNK = 0x0EB03378F1B88779
HEAD = 0x8CCA8


class X5Emu(D.DbgEmu):
    def __init__(self, cfg=None):
        super().__init__(cfg)
        self.x5_hits = []          # (pc, head_idx) where x5 became junk
        self.head_i = 0
        self.prev_x5 = 0
        self.bl_log = []           # (pc, target) of every bl in builder range
        self.wrote = []            # (pc) str/ldr near hits
        # hook every instruction in the builder to catch x5 writes
        self.mu.hook_add(UC_HOOK_CODE, self.hook_win, begin=0x8D6F4, end=0x95FC4)
        # log all bl targets inside the builder (find which helpers run late)
        self.mu.hook_add(UC_HOOK_CODE, self.hook_head2, begin=HEAD, end=HEAD)

    def hook_head2(self, uc, address, size, ud):
        self.head_i += 1
        x5 = uc.reg_read(UC_ARM64_REG_X5)
        if x5 == JUNK and self.prev_x5 != JUNK:
            print("x5=junk first seen at head pass #%d; trail:" % self.head_i)
            print("  " + " ".join(hex(a) for a in self._trail[-40:]))
        self.prev_x5 = x5

    def hook_win(self, uc, address, size, ud):
        x5 = uc.reg_read(UC_ARM64_REG_X5)
        if x5 == JUNK and (not self.x5_hits or self.x5_hits[-1][0] != address):
            if not self.x5_hits or len(self.x5_hits) < 400:
                self.x5_hits.append((address, self.head_i))
                if len(self.x5_hits) <= 12:
                    print("x5==junk at pc=0x%x (head #%d)" % (address, self.head_i))
            # stop early once we have the first hit context
            if len(self.x5_hits) == 1:
                # snapshot regs
                self.snap = {("x%d" % i): uc.reg_read(UC_ARM64_REG_X0 + i)
                             for i in range(29)}
                self.snap["sp"] = uc.reg_read(UC_ARM64_REG_SP)
                print("  regs at first x5=junk: " + " ".join(
                    "%s=0x%x" % (k, v) for k, v in self.snap.items()))


def main():
    e = X5Emu()
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    print("stopped=%s" % st)
    print("\nunique pcs where x5==junk (first 40):")
    seen = []
    for pc, hi in e.x5_hits:
        if pc not in seen:
            seen.append(pc)
    for pc in seen[:40]:
        n = sum(1 for p, _ in e.x5_hits if p == pc)
        print("  0x%x  x%d" % (pc, n))
    print("\npoll phases (x8 at 0x8d364):")
    prev = None
    for row in e.poll_exec:
        if prev is None or row[1] != prev[1]:
            D._dump_row(row)
        prev = row


if __name__ == "__main__":
    main()
