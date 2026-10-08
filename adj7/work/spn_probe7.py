"""spn_probe7.py — capture heap snapshots at SPN round boundaries.

Round-op write-count anchors from v9_ops.txt (chunk 0):
  table-gen done ~5735024, 0x1161@5739035, rounds..., final ops end 6226294
Snapshots: after table-gen, after each round's 0x1177/0x1188, after 0x1157.

    python spn_probe7.py
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
from unicorn import UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UcError
from unicorn.arm64_const import *

SEC = 1771238644
SNAP_AT = 5_300_000
REG_LIST = [UC_ARM64_REG_X0 + i for i in range(31)] + \
           [UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_NZCV]
VREGS = [UC_ARM64_REG_V0 + i for i in range(32)]
REGIONS = [(0x400000, 0x51e000), (0x5000000, 0x1000), (0x6000000, 0x1000),
           (0x7000000, 0x200000), (0x9000000, 0x800000),
           (0xB000000, 0x2000), (0xD0000000, 0x10000),
           (0xE0000000, 0x100000)]

# round-boundary write counts (0x1177 / 0x1188 dispatch moments = round end)
ANCHORS = [5735024, 5739035, 5770336, 5805637, 5840938, 5884739 - 3849,
           5915540, 5950841, 5986142, 6021443, 6056744, 6092045, 6127346,
           6162647, 6197949, 6200409, 6208540, 6216625, 6224776, 6226294]


def swap4(b):
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b) - 3, 4))


class Probe(base.Emu):
    def __init__(self, sec, anchors):
        super().__init__(verbose=False)
        self.fixed_time = sec
        self.nrand = 0
        self._on = False
        self.wc = 0
        self.snap = None
        self.anchors = set(anchors)
        self.caps = {}
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
        return r

    def on_read(self, uc, access, address, size, value, user):
        pass

    def on_write(self, uc, access, address, size, value, user):
        self.wc += 1
        if self.snap is None and self.wc == SNAP_AT:
            self.take_snapshot(uc)
        elif self.wc in self.anchors and self.snap is not None:
            heap = bytes(self.uc.mem_read(0x9000000, 0x800000))
            self.caps[self.wc] = heap
            print("  captured @wc=%d" % self.wc)

    def jni_call(self, uc, idx, x):
        if idx == 208 and x[3] == 304:
            self.out_buf = x[4]
        return super().jni_call(uc, idx, x)

    def _ensure_mapped(self, uc):
        for lo, sz in REGIONS:
            for off in range(0, sz, 0x1000):
                try:
                    uc.mem_read(lo + off, 1)
                except UcError:
                    try:
                        uc.mem_map(lo + off, 0x1000)
                    except UcError:
                        pass

    def take_snapshot(self, uc):
        self._ensure_mapped(uc)
        regs = uc.reg_read_batch(REG_LIST)
        vregs = uc.reg_read_batch(VREGS)
        mem = {}
        for lo, sz in REGIONS:
            mem[(lo, sz)] = bytes(uc.mem_read(lo, sz))
        st = {"rng": (list(self.rng.r), self.rng.f, self.rng.b),
              "brk": self.brk, "freelist": list(self.freelist),
              "sizes": dict(self.sizes), "nrand": self.nrand}
        self.snap = (regs, vregs, mem, st, uc.reg_read(UC_ARM64_REG_PC))
        print("snapshot at wc=%d t=%.1f" % (self.wc, time.time() - self.t0))
        uc.emu_stop()

    def restore(self, uc):
        regs, vregs, mem, st, pc = self.snap
        for lo, sz in REGIONS:
            uc.mem_write(lo, mem[(lo, sz)])
        uc.reg_write_batch(list(zip(REG_LIST, regs)))
        uc.reg_write_batch(list(zip(VREGS, vregs)))
        self.rng.r = list(st["rng"][0])
        self.rng.f, self.rng.b = st["rng"][1], st["rng"][2]
        self.brk = st["brk"]
        self.freelist = list(st["freelist"])
        self.sizes = dict(st["sizes"])
        return pc

    def resume(self, stop_wc=None):
        uc = self.uc
        pc = self.restore(uc)
        self.stop = stop_wc
        self.wc = 0
        try:
            uc.emu_start(pc, 0xDEAD0000, timeout=3600 * 1000000,
                         count=3000000000)
        except UcError as e:
            print("resume UcError:", e)
        self.stop = None


def main():
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])
    emu = Probe(SEC, ANCHORS)
    uc = emu.uc
    sp = 0x7000000 + 0x200000 - 0x10000
    payref = emu.newobj("bytearray", bytearray(bytes(32)))
    mapref = emu.newobj("map", dict(params))
    ctxref = emu.newobj("context", {})
    uc.reg_write(UC_ARM64_REG_TPIDR_EL0, emu.tls)
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_X0, emu.env_ptr)
    uc.reg_write(UC_ARM64_REG_X1, 0x1234)
    uc.reg_write(UC_ARM64_REG_X2, ctxref)
    uc.reg_write(UC_ARM64_REG_X3, mapref)
    uc.reg_write(UC_ARM64_REG_X4, payref)
    uc.reg_write(UC_ARM64_REG_X5, 8)
    uc.reg_write(UC_ARM64_REG_LR, 0xDEAD0000)
    try:
        uc.emu_start(base.BASE + 0xa95ac, 0xDEAD0000, timeout=600 * 1000000,
                     count=3000000000)
    except UcError as e:
        if emu.snap is None:
            print("phase1 UcError:", e)
    if emu.snap is None:
        print("NO SNAPSHOT")
        return
    emu.resume()
    outd = os.path.join(HERE, "spn_caps")
    os.makedirs(outd, exist_ok=True)
    for wc, heap in sorted(emu.caps.items()):
        with open(os.path.join(outd, "cap_%d.bin" % wc), "wb") as f:
            f.write(heap)
    print("saved %d captures to spn_caps/" % len(emu.caps))


if __name__ == "__main__":
    main()
