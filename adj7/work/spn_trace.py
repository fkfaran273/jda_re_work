"""spn_trace.py - native instruction trace of chunk-0 SPN (init..tail).

Resume from the wc=5.3M snapshot.  A single-PC dispatch hook (0x4b833c)
watches every VM opcode; when it sees 0x1161 (chunk init) it activates a
full code+mem trace; at the 2nd 0x1188 it stops.  Logs:
    D <op>                     VM opcode dispatch
    I <pc>                     native instruction (lib range)
    R/W <pc> <addr> <size> <val>
Output: spn_tr1.txt

    python spn_trace.py
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
from unicorn import (UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_HOOK_CODE,
                     UcError)
from unicorn.arm64_const import *

SEC = 1771238644
SNAP_AT = 5_300_000
DISPATCH_PC = 0x4B833C
REG_LIST = [UC_ARM64_REG_X0 + i for i in range(31)] + \
           [UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_NZCV]
VREGS = [UC_ARM64_REG_V0 + i for i in range(32)]
REGIONS = [(0x400000, 0x51e000), (0x5000000, 0x1000), (0x6000000, 0x1000),
           (0x7000000, 0x200000), (0x9000000, 0x800000),
           (0xB000000, 0x2000), (0xD0000000, 0x10000),
           (0xE0000000, 0x100000)]


class Trace(base.Emu):
    def __init__(self, sec):
        super().__init__(verbose=False)
        self.fixed_time = sec
        self.nrand = 0
        self._on = False
        self.wc = 0
        self.snap = None
        self.tracing = False
        self.f = None
        self.tail_seen = False
        self.t0 = time.time()

    def plt_dispatch(self, uc, name):
        r = super().plt_dispatch(uc, name)
        if name in ("rand", "random"):
            self.nrand += 1
            if self.nrand == 8 and not self._on:
                self._on = True
                self.uc.hook_add(UC_HOOK_MEM_WRITE, self.on_write,
                                 begin=0x7000000, end=0x9800000)
        return r

    def on_write(self, uc, access, address, size, value, user):
        self.wc += 1
        if self.snap is None and self.wc == SNAP_AT:
            self.take_snapshot(uc)

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
        print("snapshot at wc=%d pc=%#x t=%.1f"
              % (self.wc, self.snap[4], time.time() - self.t0))
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

    def tr_code(self, uc, address, size, user):
        if self.tracing and 0x400000 <= address < 0x520000:
            self.f.write("I %x\n" % address)

    def tr_read(self, uc, access, address, size, value, user):
        if not self.tracing:
            return
        try:
            v = int.from_bytes(uc.mem_read(address, size), "little")
        except UcError:
            v = 0
        self.f.write("R %x %x %d %x\n"
                     % (uc.reg_read(UC_ARM64_REG_PC), address, size, v))

    def tr_write(self, uc, access, address, size, value, user):
        if not self.tracing:
            return
        self.f.write("W %x %x %d %x\n"
                     % (uc.reg_read(UC_ARM64_REG_PC), address, size,
                        value & ((1 << (8 * size)) - 1)))

    def tr_dispatch(self, uc, address, size, user):
        op = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
        if not self.tracing:
            if op == 0x1161:
                self.tracing = True
                self.f = open(os.path.join(HERE, "spn_tr1.txt"), "w")
                uc.hook_add(UC_HOOK_CODE, self.tr_code, begin=0x400000,
                            end=0x520000)
                uc.hook_add(UC_HOOK_MEM_READ, self.tr_read,
                            begin=0x5000000, end=0x9900000)
                uc.hook_add(UC_HOOK_MEM_WRITE, self.tr_write,
                            begin=0x5000000, end=0x9900000)
                print("trace ON (0x1161 dispatch) wc=%d" % self.wc)
            return
        self.f.write("D %x\n" % op)
        if op == 0x1188:
            if self.tail_seen:
                self.tracing = False
                self.f.close()
                print("trace OFF (2nd 0x1188) wc=%d" % self.wc)
                uc.emu_stop()
            self.tail_seen = True

    def resume(self):
        uc = self.uc
        pc = self.restore(uc)
        self.wc = 0
        uc.hook_add(UC_HOOK_CODE, self.tr_dispatch, begin=DISPATCH_PC,
                    end=DISPATCH_PC)
        try:
            uc.emu_start(pc, 0xDEAD0000, timeout=3600 * 1000000,
                         count=3000000000)
        except UcError as e:
            print("resume UcError:", e)


def main():
    emu = Trace(SEC)
    uc = emu.uc
    sp = 0x7000000 + 0x200000 - 0x10000
    payref = emu.newobj("bytearray", bytearray(bytes(32)))
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])
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
        uc.emu_start(base.BASE + 0xa95ac, 0xDEAD0000, timeout=900 * 1000000,
                     count=3000000000)
    except UcError as e:
        if emu.snap is None:
            print("phase1 UcError:", e)
    if emu.snap is None:
        print("NO SNAPSHOT")
        return
    emu.resume()
    if emu.tracing and emu.f:
        emu.f.close()
        emu.tracing = False
    print("done t=%.1f" % (time.time() - emu.t0))


if __name__ == "__main__":
    main()
