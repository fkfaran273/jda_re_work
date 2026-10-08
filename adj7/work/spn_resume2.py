"""spn_resume2.py — diffusion fingerprint of the SPN.

Snapshot at wc=5.3M (before chunk-0 SPN).  For each IV byte position j:
patch IV[j] ^= 0xFF everywhere, resume, stop right after chunk-0's copy
loop, read the chunk-0 output buffer -> which output bytes depend on which
input bytes.

    python spn_resume2.py [mode]
      mode=fingerprint (default): 16 single-byte patches + identity
      mode=full: identity + iv0 patch, run to completion (chain check)
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
CHUNK0_BUF = 0x900f09c          # 16 stride-4 byte cells
STOP_AT = 6_625_000             # after chunk-0 copy loop (last store 6622147)

REG_LIST = [UC_ARM64_REG_X0 + i for i in range(31)] + \
           [UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_NZCV]
VREGS = [UC_ARM64_REG_V0 + i for i in range(32)]
REGIONS = [(0x400000, 0x51e000), (0x5000000, 0x1000), (0x6000000, 0x1000),
           (0x7000000, 0x200000), (0x9000000, 0x800000),
           (0xB000000, 0x2000), (0xD0000000, 0x10000),
           (0xE0000000, 0x100000)]


def swap4(b):
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b) - 3, 4))


class ResumeProbe(base.Emu):
    def __init__(self, sec):
        super().__init__(verbose=False)
        self.fixed_time = sec
        self.nrand = 0
        self._on = False
        self.wc = 0
        self.snap = None
        self.stop_wc = None
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
        elif self.stop_wc is not None and self.wc >= self.stop_wc:
            uc.emu_stop()

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

    def run_patched(self, iv_new, stop_wc=None):
        uc = self.uc
        pc = self.restore(uc)
        iv_old = self.iv_original
        heap0 = self.snap[2][(0x9000000, 0x800000)]
        stack0 = self.snap[2][(0x7000000, 0x200000)]
        npat = 0
        for name, buf, base_ in (("h", heap0, 0x9000000),
                                 ("s", stack0, 0x7000000)):
            for pat, rep in ((iv_old, iv_new),
                             (swap4(iv_old), swap4(iv_new))):
                i = buf.find(pat)
                while i != -1:
                    uc.mem_write(base_ + i, rep)
                    npat += 1
                    i = buf.find(pat, i + 1)
            for k in range(4):
                wo = iv_old[4 * k:4 * k + 4]
                wn = iv_new[4 * k:4 * k + 4]
                for fo, fr in ((wo, wn), (wo[::-1], wn[::-1])):
                    j = buf.find(fo)
                    while j != -1:
                        uc.mem_write(base_ + j, fr)
                        npat += 1
                        j = buf.find(fo, j + 1)
        self.stop_wc = stop_wc
        self.wc = 0
        try:
            uc.emu_start(pc, 0xDEAD0000, timeout=600 * 1000000,
                         count=3000000000)
        except UcError as e:
            print("  resume UcError:", e)
        if stop_wc is not None:
            buf = bytes(uc.mem_read(CHUNK0_BUF, 64))
            out = bytes(buf[4 * i] for i in range(16))
            self.stop_wc = None
            return out, None
        for p, ref in self.elem_map.items():
            tgt = self.heap_objs.get(ref)
            if tgt and tgt.val is not None:
                try:
                    tgt.val[:] = bytes(uc.mem_read(p, len(tgt.val)))
                except UcError:
                    pass
        o = self.heap_objs.get(uc.reg_read(UC_ARM64_REG_X0))
        blob = bytes(o.val) if o and o.kind == "bytearray" else None
        if blob is None and self.out_buf is not None:
            blob = bytes(uc.mem_read(self.out_buf, 304))
        return None, blob


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "fingerprint"
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])
    emu = ResumeProbe(SEC)
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
    blob0 = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read()
                          .strip())
    emu.iv_original = blob0[:16]
    print("IV:", emu.iv_original.hex())
    chunk0_ref = blob0[16:32]

    if mode == "fingerprint":
        # identity baseline via early stop
        c0, _ = emu.run_patched(emu.iv_original, stop_wc=STOP_AT)
        print("chunk0(identity) =", c0.hex() if c0 else None)
        print("matches blob     :", c0 == chunk0_ref if c0 else False)
        print()
        for j in range(16):
            iv = bytearray(emu.iv_original)
            iv[j] ^= 0xFF
            t = time.time()
            c0, _ = emu.run_patched(bytes(iv), stop_wc=STOP_AT)
            if c0 is None:
                print("j=%2d FAILED" % j)
                continue
            diff = [i for i in range(16) if c0[i] != chunk0_ref[i]]
            print("j=%2d -> diff out bytes: %s   (%.1fs)"
                  % (j, diff, time.time() - t))
    elif mode == "full":
        _, b1 = emu.run_patched(emu.iv_original)
        print("identity blob ok:", b1 == blob0 if b1 else None)
        iv = bytearray(emu.iv_original)
        iv[0] ^= 0xFF
        _, b2 = emu.run_patched(bytes(iv))
        if b1 and b2:
            diff = [i for i in range(304) if b1[i] != b2[i]]
            chunks = sorted(set((i - 16) // 16 for i in diff
                                if 16 <= i < 272))
            print("iv0^ff full diff: header bytes %s; chunks touched %s"
                  % ([i for i in diff if i < 16], chunks))


if __name__ == "__main__":
    main()
