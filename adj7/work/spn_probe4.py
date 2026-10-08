"""spn_probe4.py — unified interleaved read+write event log (with read
values re-read from memory inside the hook), covering the whitening start
through chunk 0's byte loop (write ~6.65M).

    python spn_probe4.py
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
STOP_WRITES = 6_650_000


class Probe(base.Emu):
    def __init__(self, sec):
        super().__init__(verbose=False)
        self.fixed_time = sec
        self.nrand = 0
        self._on = False
        self.wc = 0
        self.f = open(os.path.join(HERE, "v7_events.txt"), "w")
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
        self.wc += 1
        if self.wc <= STOP_WRITES:
            self.f.write("W %x %x %d %x\n" % (uc.reg_read(UC_ARM64_REG_PC),
                                              address, size, value))
        elif not self.f.closed:
            self.f.close()
            print("log closed at wc=%d t=%.1f" % (self.wc,
                                                  time.time() - self.t0))

    def on_read(self, uc, access, address, size, value, user):
        if self.f.closed:
            return
        if size == 1:
            v = uc.mem_read(address, 1)[0]
        elif size == 4:
            v = int.from_bytes(uc.mem_read(address, 4), "little")
        elif size == 8:
            v = int.from_bytes(uc.mem_read(address, 8), "little")
        else:
            v = int.from_bytes(uc.mem_read(address, size), "little")
        self.f.write("R %x %x %d %x\n" % (uc.reg_read(UC_ARM64_REG_PC),
                                          address, size, v))

    def run(self, payload=bytes(32), mapobj=None, arg4=8):
        out = super().run(payload=payload, mapobj=mapobj, arg4=arg4)
        if not self.f.closed:
            self.f.close()
        return out


def main():
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])
    emu = Probe(SEC)
    blob = emu.run(payload=bytes(32), mapobj=params)
    want = open(os.path.join(HERE, "v3_blob.hex")).read().strip()
    print("blob match:", blob is not None and blob.hex() == want,
          "t=%.1f" % (time.time() - emu.t0))


if __name__ == "__main__":
    main()
