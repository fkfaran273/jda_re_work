"""commit2_probe.py — one fresh mint with full VM-bus instrumentation.

Records, after the 8th rand():
  * every write to the value bus 0x71ef67c           (idx, value)
  * every write to heap [0x9000000,0x9200000)        (idx, addr, size, value)
  * every READ with its value, deduped consecutively (idx, addr, size, value)

The write stream is segmented into SHA-256 runs (FIPS IV init) and the
message words of each run are recovered from the bus/reads.

    python commit2_probe.py [sec]
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
os.chdir(WORK)
sys.path.insert(0, WORK)
sys.path.insert(0, HERE)

import adj7s3_emu as base
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_PC

SEC = int(sys.argv[1]) if len(sys.argv) > 1 else 1771238644
BUS = 0x71EF67C
PC = 0x9005210


class Probe(base.Emu):
    def __init__(self, sec):
        super().__init__(verbose=False)
        self.fixed_time = sec
        self.out_buf = None
        self.nrand = 0
        self._on = False
        self.bus = []          # (idx, value)  writes to BUS
        self.wr = []           # (idx, addr, size, value) heap writes
        self.rd = []           # (idx, addr, size, value) reads (deduped)
        self._rdlast = None
        self.pcvals = []       # (idx, pc)
        self.blob = None

    def plt_dispatch(self, uc, name):
        r = super().plt_dispatch(uc, name)
        if name in ("rand", "random"):
            self.nrand += 1
            if self.nrand == 8 and not self._on:
                self._on = True
                self.uc.hook_add(UC_HOOK_MEM_WRITE, self.on_write,
                                 begin=0x7000000, end=0x9200000)
                self.uc.hook_add(UC_HOOK_MEM_READ, self.on_read,
                                 begin=0x7000000, end=0x9200000)
        return r

    def on_write(self, uc, access, address, size, value, user):
        i = len(self.wr) + len(self.bus)
        if address == BUS:
            self.bus.append((i, value & 0xFFFFFFFFFFFFFFFF))
        else:
            self.wr.append((i, address, size, value & 0xFFFFFFFFFFFFFFFF))

    def on_read(self, uc, access, address, size, value, user):
        v = value & 0xFFFFFFFFFFFFFFFF
        key = (address, size, v)
        if key != self._rdlast:
            self._rdlast = key
            self.rd.append((len(self.wr) + len(self.bus), address, size, v))

    def jni_call(self, uc, idx, x):
        if idx == 208 and x[3] == 304:
            self.out_buf = x[4]
        return super().jni_call(uc, idx, x)

    def run(self, payload=bytes(32), mapobj=None, arg4=8):
        out = super().run(payload=payload, mapobj=mapobj, arg4=arg4)
        if out is None and self.out_buf is not None:
            out = bytes(self.uc.mem_read(self.out_buf, 304))
        self.blob = out
        return out


def main():
    bodies = {b["sid"]: b for b in json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])
    emu = Probe(SEC)
    blob = emu.run(mapobj=params)
    print("sec", SEC, "bus", len(emu.bus), "wr", len(emu.wr),
          "rd", len(emu.rd), "blob", (blob or b"").hex()[:48])
    heap = bytes(emu.uc.mem_read(base.HEAP, emu.brk - base.HEAP))
    open(os.path.join(HERE, "commit2_probe_heap.bin"), "wb").write(heap)
    if blob:
        open(os.path.join(HERE, "commit2_probe_blob.hex"), "w").write(blob.hex())
    import struct as _s
    with open(os.path.join(HERE, "commit2_bus.bin"), "wb") as f:
        for i, v in emu.bus:
            f.write(_s.pack("<QQ", i, v))
    with open(os.path.join(HERE, "commit2_wr.bin"), "wb") as f:
        for i, a, s, v in emu.wr:
            f.write(_s.pack("<QQIQ", i, a, s, v))
    with open(os.path.join(HERE, "commit2_rd.bin"), "wb") as f:
        for i, a, s, v in emu.rd:
            f.write(_s.pack("<QQIQ", i, a, s, v))
    print("saved commit2_bus.bin / commit2_wr.bin / commit2_rd.bin / heap")


if __name__ == "__main__":
    main()
