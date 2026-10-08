"""probe_v3.py — full whitening data-flow capture.

Arms read(addr,size)+write(addr,size,value) hooks over heap+stack at the
whitening start (8th plt rand()), snapshots memory at pass boundaries
(trigger dword 0x900a140 read), and dumps everything for offline mining.

    python probe_v3.py [sec]
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
TRIGGER = 0x900a140

class Probe(base.Emu):
    def __init__(self, sec):
        super().__init__(verbose=False)
        self.fixed_time = sec
        self.out_buf = None
        self.nrand = 0
        self._on = False
        self.reads = []       # (addr, size)
        self.writes = []      # (addr, size, value)
        self.passn = 0
        self.snaps = {}       # passn -> (heap_hex, stack_hex)

    def plt_dispatch(self, uc, name):
        r = super().plt_dispatch(uc, name)
        if name in ("rand", "random"):
            self.nrand += 1
            if self.nrand == 8 and not self._on:
                self._on = True
                self.uc.hook_add(UC_HOOK_MEM_READ, self.on_read,
                                 begin=0x7000000, end=0x9200000)
                self.uc.hook_add(UC_HOOK_MEM_WRITE, self.on_write,
                                 begin=0x7000000, end=0x9200000)
        return r

    def on_read(self, uc, access, address, size, value, user):
        self.reads.append((address, size))
        if address == TRIGGER and size == 4:
            self.passn += 1
            if self.passn in (1, 2, 9, 16):
                try:
                    heap = bytes(uc.mem_read(0x9000000, self.brk - 0x9000000))
                    stack = bytes(uc.mem_read(0x71e0000, 0x20000))
                    self.snaps[self.passn] = (heap, stack)
                except Exception as e:
                    print("snap err", e)

    def on_write(self, uc, access, address, size, value, user):
        self.writes.append((address, size, value))

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
    bodies = {b["sid"]: b for b in json.load(open("adj7b_bodies.json"))}
    params = dict(bodies["0015"]["body_params_dict"])
    emu = Probe(SEC)
    blob = emu.run(mapobj=params)
    print("sec", SEC, "blob", blob.hex()[:48], "passes", emu.passn,
          "reads", len(emu.reads), "writes", len(emu.writes),
          "snaps", sorted(emu.snaps))
    with open(os.path.join(HERE, "v3_writes.txt"), "w") as f:
        for a, s, v in emu.writes:
            f.write("%x %d %x\n" % (a, s, v))
    with open(os.path.join(HERE, "v3_reads.txt"), "w") as f:
        for a, s in emu.reads:
            f.write("%x %d\n" % (a, s))
    for p, (heap, stack) in emu.snaps.items():
        with open(os.path.join(HERE, f"v3_snap_p{p}_heap.bin"), "wb") as f:
            f.write(heap)
        with open(os.path.join(HERE, f"v3_snap_p{p}_stack.bin"), "wb") as f:
            f.write(stack)
    with open(os.path.join(HERE, "v3_blob.hex"), "w") as f:
        f.write(blob.hex())
    print("saved v3_* files")

if __name__ == "__main__":
    main()
