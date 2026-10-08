"""spn_oracle3.py — sweep chunk-0 input byte 0, capture S_init + round-1
quad output per run (dispatch-hook stops, clean instruction boundaries).

    python spn_oracle3.py sweep [byte]     -> spn_sweep_b<byte>.json
    python spn_oracle3.py probe            - 3 sanity runs
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

import spn_resume2 as sr2
import adj7s3_emu as base
from unicorn import UC_HOOK_CODE, UcError
from unicorn.arm64_const import *

SEC = 1771238644
DISPATCH_PC = 0x4B833C
BUF = 0x900F09C
IV = bytes.fromhex("66e7ca6832cb9e2210a0eba90d27c4c2")


def swap4(b):
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b) - 3, 4))


class SweepProbe(sr2.ResumeProbe):
    def __init__(self, sec):
        super().__init__(sec)
        self.targets = []
        self.reads = []

    def on_dispatch(self, uc, address, size, user):
        if not self.targets:
            return
        op = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
        if op == self.targets[0]:
            self.targets.pop(0)
            buf = bytes(uc.mem_read(BUF, 64))
            self.reads.append(bytes(buf[4 * i] for i in range(16)))
            if not self.targets:
                uc.emu_stop()

    def run_input(self, iv_new):
        uc = self.uc
        pc = self.restore(uc)
        # patch IV material everywhere (same as spn_resume2.run_patched)
        iv_old = self.iv_original
        heap0 = self.snap[2][(0x9000000, 0x800000)]
        stack0 = self.snap[2][(0x7000000, 0x200000)]
        for name, buf, base_ in (("h", heap0, 0x9000000),
                                 ("s", stack0, 0x7000000)):
            for pat, rep in ((iv_old, iv_new), (swap4(iv_old), swap4(iv_new))):
                i = buf.find(pat)
                while i != -1:
                    uc.mem_write(base_ + i, rep)
                    i = buf.find(pat, i + 1)
            for k in range(4):
                wo = iv_old[4 * k:4 * k + 4]
                wn = iv_new[4 * k:4 * k + 4]
                for fo, fr in ((wo, wn), (wo[::-1], wn[::-1])):
                    j = buf.find(fo)
                    while j != -1:
                        uc.mem_write(base_ + j, fr)
                        j = buf.find(fo, j + 1)
        self.reads = []
        self.targets = [0x1168, 0x1172, 0x1177, 0x1168]  # S_init, quadout, m1, m2
        h = uc.hook_add(UC_HOOK_CODE, self.on_dispatch, begin=DISPATCH_PC,
                        end=DISPATCH_PC)
        self.wc = 0
        self.stop_wc = None
        try:
            uc.emu_start(pc, 0xDEAD0000, timeout=600 * 1000000,
                         count=3000000000)
        except UcError as e:
            print("  run UcError:", e)
        uc.hook_del(h)
        return self.reads


def make_emu():
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])
    emu = SweepProbe(SEC)
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
        uc.emu_start(base.BASE + 0xa95ac, 0xDEAD0000, timeout=900 * 1000000,
                     count=3000000000)
    except UcError as e:
        if emu.snap is None:
            print("phase1 UcError:", e)
    if emu.snap is None:
        raise SystemExit("NO SNAPSHOT")
    blob0 = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
    emu.iv_original = blob0[:16]
    return emu


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "probe"
    emu = make_emu()
    if mode == "probe":
        r = emu.run_input(IV)
        print("stops:", [x.hex() for x in r])
        print("S_init ok :", r[0] == bytes.fromhex(
            "ce0e7d52f5def2c3b291af7442ce9147"))
        print("quadout ok:", r[1] == bytes.fromhex(
            "16c49cb69a36aba08871d8e310272fd2"))
        r = emu.run_input(bytes(a ^ 0xFF for a in IV))
        print("xorff S_init :", r[0].hex())
        print("xorff quadout:", r[1].hex())
    elif mode == "sweep":
        byte = int(sys.argv[2]) if len(sys.argv) > 2 else 0
        res = []
        t0 = time.time()
        for v in range(256):
            iv = bytearray(IV)
            iv[byte] = v
            r = emu.run_input(bytes(iv))
            res.append((r[0].hex(), r[1].hex()))
            if v % 32 == 31:
                print("  %d/256 (%.0fs)" % (v + 1, time.time() - t0))
        with open(os.path.join(HERE, "spn_sweep_b%d.json" % byte), "w") as f:
            json.dump(res, f)
        print("saved spn_sweep_b%d.json" % byte)


if __name__ == "__main__":
    main()
