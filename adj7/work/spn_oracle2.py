"""spn_oracle2.py — state-patching oracle for the chunk-0 SPN round 1.

Phase 1 snapshots at the 0x1168 r1 dispatch (global wc 6,152,725), i.e. the
moment the buffer + stack hold S_init and round 1 is about to start.
Then: patch the state (16-B patterns on stack+heap, like spn_resume2's IV
patcher), resume to the 0x1172 r1 dispatch (post wc 875,895), read the
buffer = quad-layer output for the patched state.

    python spn_oracle2.py probe           - find state patterns, test 1 flip
    python spn_oracle2.py cellmap <cell>  - sweep 256 values of one cell
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
from unicorn import UcError
from unicorn.arm64_const import *

SEC = 1771238644
SNAP_GLOBAL = 6_152_725          # 0x1168 r1 dispatch (global wc)
S_INIT = bytes.fromhex("ce0e7d52f5def2c3b291af7442ce9147")
POST_0x1172_R1 = 875_895         # 0x1172 r1 dispatch +2 (post-resume wc)
BUF = 0x900F09C
STACK_LO, STACK_SZ = 0x7000000, 0x200000
HEAP_LO, HEAP_SZ = 0x9000000, 0x800000


def swap4(b):
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b) - 3, 4))


class StateProbe(sr2.ResumeProbe):
    """snapshot at SNAP_GLOBAL instead of 5.3M"""

    def __init__(self, sec):
        super().__init__(sec)

    def on_write(self, uc, access, address, size, value, user):
        self.wc += 1
        if self.snap is None and self.wc == SNAP_GLOBAL:
            self.take_snapshot(uc)
        elif self.stop_wc is not None and self.wc >= self.stop_wc:
            uc.emu_stop()


def make_emu():
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])
    emu = StateProbe(SEC)
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
    return emu


def find_patches(uc, old, new):
    """patch every occurrence of old (16B / swap4 / word forms) -> new"""
    n = 0
    for base_, size in ((HEAP_LO, HEAP_SZ), (STACK_LO, STACK_SZ)):
        buf = bytes(uc.mem_read(base_, size))
        for pat, rep in ((old, new), (swap4(old), swap4(new))):
            i = buf.find(pat)
            while i != -1:
                uc.mem_write(base_ + i, rep)
                n += 1
                i = buf.find(pat, i + 1)
        for k in range(4):
            wo = old[4 * k:4 * k + 4]
            wn = new[4 * k:4 * k + 4]
            for fo, fr in ((wo, wn), (wo[::-1], wn[::-1])):
                j = buf.find(fo)
                while j != -1:
                    uc.mem_write(base_ + j, fr)
                    n += 1
                    j = buf.find(fo, j + 1)
    return n


def run_round1(emu, new_state):
    """restore, patch state -> new_state, run to 0x1172 r1, read buffer."""
    uc = emu.uc
    pc = emu.restore(uc)
    emu.wc = 0
    emu.stop_wc = None
    n = find_patches(uc, S_INIT, new_state)
    # run to 0x1172 r1 dispatch
    emu.stop_wc = POST_0x1172_R1
    try:
        uc.emu_start(pc, 0xDEAD0000, timeout=600 * 1000000, count=3000000000)
    except UcError as e:
        print("  run UcError:", e)
    emu.stop_wc = None
    buf = bytes(uc.mem_read(BUF, 64))
    out = bytes(buf[4 * i] for i in range(16))
    return out, n


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "probe"
    emu = make_emu()
    if mode == "probe":
        # verify identity: unpatched run reproduces the real round-1 quadout
        ref = bytes.fromhex("16c49cb69a36aba08871d8e310272fd2")
        out, n = run_round1(emu, S_INIT)
        print("identity: %s  patches=%d  match=%s" % (out.hex(), n, out == ref))
        # propagation test: flip byte 0
        ns = bytearray(S_INIT)
        ns[0] ^= 0xFF
        out, n = run_round1(emu, bytes(ns))
        print("flip b0 : %s  patches=%d" % (out.hex(), n))
        diff = [i for i in range(16) if out[i] != ref[i]]
        print("diff cells:", diff)
    elif mode == "cellmap":
        cell = int(sys.argv[2])
        ref = bytes.fromhex("16c49cb69a36aba08871d8e310272fd2")
        res = {}
        for v in range(256):
            ns = bytearray(S_INIT)
            ns[cell] = v
            out, n = run_round1(emu, bytes(ns))
            res[v] = out[cell]
            if v % 32 == 31:
                print("  cell %d: %d/256 done" % (cell, v + 1))
        with open(os.path.join(HERE, "spn_cellmap_%d.json" % cell), "w") as f:
            json.dump({"cell": cell, "map": ["%02x" % res[v] for v in range(256)]}, f)
        print("saved spn_cellmap_%d.json" % cell)
        # quick stats
        diffcount = sum(1 for v in range(256) if res[v] != ref[cell])
        print("outputs differing from ref at cell %d: %d" % (cell, diffcount))


if __name__ == "__main__":
    main()
