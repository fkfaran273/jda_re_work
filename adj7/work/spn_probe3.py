"""spn_probe3.py — mint with PC-attributed memory event logs.

Logs every heap+stack write as (pc addr size value) and every read as
(pc addr size) from the whitening start.  pc = uc.reg_read(PC) inside the
hook = the accessing instruction.

    python spn_probe3.py
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
os.chdir(WORK)
sys.path.insert(0, WORK)
sys.path.insert(0, HERE)

import adj7s3_emu as base
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_PC

SEC = 1771238644


class Probe(base.Emu):
    def __init__(self, sec):
        super().__init__(verbose=False)
        self.fixed_time = sec
        self.nrand = 0
        self._on = False
        self.w = open(os.path.join(HERE, "v6_writes.txt"), "w")
        self.r = open(os.path.join(HERE, "v6_reads.txt"), "w")
        self.nw = 0
        self.nr = 0
        self.t0 = time.time()

    def plt_dispatch(self, uc, name):
        r = super().plt_dispatch(uc, name)
        if name in ("rand", "random"):
            self.nrand += 1
            if self.nrand == 8 and not self._on:
                self._on = True
                self.uc.hook_add(UC_HOOK_MEM_WRITE, self.on_write,
                                 begin=0x7000000, end=0x9800000)
                self.uc.hook_add(UC_HOOK_MEM_READ, self.on_read,
                                 begin=0x7000000, end=0x9800000)
                print("armed t=%.1f" % (time.time() - self.t0))
        return r

    def on_write(self, uc, access, address, size, value, user):
        self.nw += 1
        self.w.write("%x %x %d %x\n" % (uc.reg_read(UC_ARM64_REG_PC),
                                        address, size, value))

    def on_read(self, uc, access, address, size, value, user):
        self.nr += 1
        self.r.write("%x %x %d\n" % (uc.reg_read(UC_ARM64_REG_PC),
                                     address, size))

    def run(self, payload=bytes(32), mapobj=None, arg4=8):
        out = super().run(payload=payload, mapobj=mapobj, arg4=arg4)
        self.w.close()
        self.r.close()
        return out


def main():
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])
    emu = Probe(SEC)
    blob = emu.run(payload=bytes(32), mapobj=params)
    want = open(os.path.join(HERE, "v3_blob.hex")).read().strip()
    got = blob.hex() if blob else ""
    print("blob match:", got == want, "writes", emu.nw, "reads", emu.nr,
          "t=%.1f" % (time.time() - emu.t0))


if __name__ == "__main__":
    main()
