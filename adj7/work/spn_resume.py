"""spn_resume.py — snapshot the emu just before the chunk phase, then resume
many times with patched IVs to fingerprint the SPN diffusion.

    python spn_resume.py            # snapshot + differential test (3 patches)
"""
import copy
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
from unicorn import UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
from unicorn.arm64_const import *
from unicorn import UcError

SEC = 1771238644
SNAP_AT = 6_600_000            # before chunk-0 byte loop (stores at 6614677)

REG_LIST = [UC_ARM64_REG_X0 + i for i in range(31)] + \
           [UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_NZCV]
# x0..x30 -> 31 regs? x0..x30 is 31 entries only if X30 exists; x30=LR yes.
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
        self.t0 = time.time()
        self.results = {}

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
        if self.wc == SNAP_AT and self.snap is None:
            self.take_snapshot(uc)

    def jni_call(self, uc, idx, x):
        if idx == 208 and x[3] == 304:
            self.out_buf = x[4]
        return super().jni_call(uc, idx, x)

    # ---------- snapshot / restore ----------
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
        st = {
            "rng": (list(self.rng.r), self.rng.f, self.rng.b),
            "brk": self.brk,
            "freelist": list(self.freelist),
            "sizes": dict(self.sizes),
            "nrand": self.nrand,
        }
        self.snap = (regs, vregs, mem, st, uc.reg_read(UC_ARM64_REG_PC))
        print("snapshot taken at wc=%d pc=%#x t=%.1f"
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

    def find_iv_locations(self, uc, iv):
        """all (addr, size) spots holding IV material: 16B direct, 16B
        swapped, 4B words in BE/LE forms."""
        spots = []
        heap = bytes(uc.mem_read(0x9000000, 0x800000))
        stack = bytes(uc.mem_read(0x7000000, 0x200000))
        for name, buf, base in (("heap", heap, 0x9000000),
                                ("stack", stack, 0x7000000)):
            for pat in (iv, swap4(iv)):
                i = buf.find(pat)
                while i != -1:
                    spots.append((base + i, 16, pat.hex()))
                    i = buf.find(pat, i + 1)
            for k in range(4):
                w = iv[4 * k:4 * k + 4]
                for form in (w, w[::-1]):
                    j = buf.find(form)
                    while j != -1:
                        spots.append((base + j, 4, "w%d" % k))
                        j = buf.find(form, j + 1)
        return spots

    def run_patched(self, iv_new, verbose=False):
        """restore snapshot, patch all IV material, resume to the end,
        return the 304-B blob."""
        uc = self.uc
        pc = self.restore(uc)
        spots = self.find_iv_locations(uc, bytes(self.snap[2][(0x9000000,
                                                               0x800000)])
                                       [:0])          # placeholder
        # find IV occurrences against the ORIGINAL snapshot bytes
        heap0 = self.snap[2][(0x9000000, 0x800000)]
        stack0 = self.snap[2][(0x7000000, 0x200000)]
        iv_old = self.iv_original
        patches = []
        for name, buf, base in (("heap", heap0, 0x9000000),
                                ("stack", stack0, 0x7000000)):
            for pat, rep in ((iv_old, iv_new), (swap4(iv_old), swap4(iv_new))):
                i = buf.find(pat)
                while i != -1:
                    patches.append((base + i, 16, rep))
                    i = buf.find(pat, i + 1)
            for k in range(4):
                w_old = iv_old[4 * k:4 * k + 4]
                w_new = iv_new[4 * k:4 * k + 4]
                for fo, fr in ((w_old, w_new), (w_old[::-1], w_new[::-1])):
                    j = buf.find(fo)
                    while j != -1:
                        patches.append((base + j, 4, fr))
                        j = buf.find(fo, j + 1)
        for addr, sz, rep in patches:
            uc.mem_write(addr, rep)
        if verbose:
            print("  patched %d spots" % len(patches))
        self.wc = 0
        self.resumed = True
        try:
            uc.emu_start(pc, 0xDEAD0000, timeout=600 * 1000000,
                         count=3000000000)
        except UcError as e:
            print("  resume UcError:", e, "pc=%#x" % uc.reg_read(
                UC_ARM64_REG_PC))
            return None
        # sync outputs like base.Emu.run tail
        for p, ref in self.elem_map.items():
            tgt = self.heap_objs.get(ref)
            if tgt and tgt.val is not None:
                try:
                    tgt.val[:] = bytes(uc.mem_read(p, len(tgt.val)))
                except UcError:
                    pass
        out_ref = uc.reg_read(UC_ARM64_REG_X0)
        o = self.heap_objs.get(out_ref)
        if o and o.kind == "bytearray":
            return bytes(o.val)
        return None


def main():
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])
    emu = ResumeProbe(SEC)
    # phase 1: run to snapshot
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
    emu.out_buf = None
    orig_jni = emu.jni_call

    def jni_spy(idx, x):
        if idx == 208 and x[3] == 304:
            emu.out_buf = x[4]
        return orig_jni(uc, idx, x) if False else None
    # simpler: wrap via jni_call override
    class Spy(ResumeProbe):
        pass
    try:
        uc.emu_start(base.BASE + 0xa95ac, 0xDEAD0000, timeout=600 * 1000000,
                     count=3000000000)
    except UcError as e:
        print("phase1 UcError:", e)
    if emu.snap is None:
        print("no snapshot; wc=", emu.wc)
        return
    # capture the original IV from memory at snapshot: search header value
    # from a full baseline run? Instead: take IV from a known full mint:
    blob0 = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read()
                          .strip())
    emu.iv_original = blob0[:16]
    print("IV:", emu.iv_original.hex())

    # phase 2: differential test
    import struct
    tests = []
    iv_a = bytearray(emu.iv_original)
    iv_b = bytearray(emu.iv_original)
    iv_b[0] ^= 0xFF
    iv_c = bytearray(emu.iv_original)
    iv_c[5] ^= 0xFF
    tests.append(("identity", bytes(iv_a)))
    tests.append(("iv0^ff", bytes(iv_b)))
    tests.append(("iv5^ff", bytes(iv_c)))
    blobs = {}
    for nm, iv in tests:
        t = time.time()
        blob = emu.run_patched(iv, verbose=True)
        if blob is None and emu.out_buf is not None:
            blob = bytes(uc.mem_read(emu.out_buf, 304))
        blobs[nm] = blob
        print("%-8s -> %s  (%.1fs)" % (nm, blob.hex()[:48] if blob else None,
                                       time.time() - t))
    # diff report
    base_blob = blobs["identity"]
    for nm in ("iv0^ff", "iv5^ff"):
        b = blobs[nm]
        if not b or not base_blob:
            continue
        diff_bytes = [i for i in range(304) if b[i] != base_blob[i]]
        chunks_touched = sorted(set((i - 16) // 16 for i in diff_bytes
                                    if 16 <= i < 272))
        per_chunk = {}
        for i in diff_bytes:
            if 16 <= i < 272:
                per_chunk.setdefault((i - 16) % 16, set()).add(
                    (i - 16) // 16)
        print(nm, "diff byte offsets in blob:", diff_bytes[:40])
        print(nm, "byte-positions within chunks:",
              {k: sorted(v) for k, v in per_chunk.items()})


if __name__ == "__main__":
    main()
