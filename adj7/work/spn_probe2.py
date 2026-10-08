"""spn_probe2.py — native instruction trace of the chunk phase.

Runs the same deterministic mint (0015 / 1771238644).  At write-count
ARM_AT a UC_HOOK_CODE over the lib code starts logging (pc, x0..x30) per
instruction; stops at STOP_AT.  Covers the tail of the per-chunk byte loops
and the whole dword-push phase.

    python spn_probe2.py
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
os.chdir(WORK)
sys.path.insert(0, WORK)
sys.path.insert(0, HERE)

import adj7s3_emu as base
from unicorn import UC_HOOK_MEM_WRITE, UC_HOOK_CODE
from unicorn import UC_HOOK_MEM_READ
from unicorn.arm64_const import *

ARM_AT = 24_900_000
STOP_AT = 25_020_000
TRACE_LO, TRACE_HI = 0x400000, 0x520000
REGS = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
        UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X10,
        UC_ARM64_REG_X11, UC_ARM64_REG_X12, UC_ARM64_REG_X13,
        UC_ARM64_REG_X14, UC_ARM64_REG_X15, UC_ARM64_REG_X16,
        UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19,
        UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22,
        UC_ARM64_REG_X23, UC_ARM64_REG_X24, UC_ARM64_REG_X25,
        UC_ARM64_REG_X26, UC_ARM64_REG_X27, UC_ARM64_REG_X28,
        UC_ARM64_REG_X29, UC_ARM64_REG_X30, UC_ARM64_REG_SP]


class Probe(base.Emu):
    def __init__(self, sec):
        super().__init__(verbose=False)
        self.fixed_time = sec
        self.nrand = 0
        self._mem = False
        self._code_on = False
        self.wc = 0
        self.trace = []
        self.t0 = time.time()

    def plt_dispatch(self, uc, name):
        r = super().plt_dispatch(uc, name)
        if name in ("rand", "random"):
            self.nrand += 1
            if self.nrand == 8 and not self._mem:
                self._mem = True
                self.uc.hook_add(UC_HOOK_MEM_WRITE, self.on_write,
                                 begin=0x7000000, end=0x9800000)
                self.uc.hook_add(UC_HOOK_MEM_READ, self.on_read,
                                 begin=0x7000000, end=0x9800000)
        return r

    def on_read(self, uc, access, address, size, value, user):
        pass

    def on_write(self, uc, access, address, size, value, user):
        self.wc += 1
        if self.wc == ARM_AT:
            self._code_on = True
            self.uc.hook_add(UC_HOOK_CODE, self.on_code,
                             begin=TRACE_LO, end=TRACE_HI)
            print("code trace armed at wc=%d t=%.1f" % (self.wc,
                                                        time.time() - self.t0))
        elif self.wc == STOP_AT:
            self._code_on = False
            print("code trace stopped at wc=%d t=%.1f lines=%d"
                  % (self.wc, time.time() - self.t0, len(self.trace)))

    def on_code(self, uc, address, size, user):
        if not self._code_on:
            return
        regs = uc.reg_read_batch(REGS)
        self.trace.append((address,) + tuple(regs))


def main():
    import json
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])
    emu = Probe(1771238644)
    blob = emu.run(payload=bytes(32), mapobj=params)
    print("blob ok:", blob is not None and blob.hex()[:32])
    with open(os.path.join(HERE, "v5_codetrace.txt"), "w") as f:
        for row in emu.trace:
            f.write("%x " % row[0] + " ".join("%x" % v for v in row[1:]) + "\n")
    print("saved v5_codetrace.txt lines=%d" % len(emu.trace))


if __name__ == "__main__":
    main()
