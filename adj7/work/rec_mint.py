"""rec_mint.py — instrumented adj7 mint for the RECORD-ASSEMBLY law.

Runs one genuine-native mint (Unicorn, adj7s3_emu) and captures:
  * full heap+stack dumps at the 8th rand() and at selected 0x1161 VM
    dispatches (the record buffer must exist around the whitening),
  * the 16 state cells (0x900F09C + 0x40k, stride-4 dwords) at every 0x1161,
  * the blob (verified against the reference).

    python rec_mint.py 0015 [0001]
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
from unicorn import UC_HOOK_CODE, UcError
from unicorn.arm64_const import *

DISPATCH_PC = 0x4B833C          # VM opcode dispatch (opcode in w0)
CELL0 = 0x900F09C               # chunk-k state cells: +0x40*k, stride 4
DUMP_REGIONS = [(0x7000000, 0x200000), (0x9000000, 0x800000)]

MINTS = {
    "0015": dict(sec=1771238644, ref="v3_blob.hex"),
    "0001": dict(sec=1789382946, ref=None),   # ref: adj7s4_out7.json out_hex
}


class RecEmu(base.Emu):
    def __init__(self, sec, tag):
        super().__init__(verbose=False)
        self.fixed_time = sec
        self.tag = tag
        self.nrand = 0
        self.rec_on = False          # NOTE: base .armed is taken (containsKey)
        self.t0 = time.time()
        self.sinit = []          # 16 B cell view at each 0x1161
        self.ops = []            # opcode stream
        self.dumps_made = []
        # code hook registered up-front (unicorn ignores hook_add from
        # inside a code-hook callback); gated on rec_on in the handler
        self.uc.hook_add(UC_HOOK_CODE, self.on_code,
                         begin=DISPATCH_PC, end=DISPATCH_PC)

    # ---------- hooks ----------
    def plt_dispatch(self, uc, name):
        r = super().plt_dispatch(uc, name)
        if name in ("rand", "random") and not self.rec_on:
            self.nrand += 1
            if self.nrand == 8:
                self.rec_on = True
                self.dump(uc, "arm")
        return r

    def on_code(self, uc, address, size, user):
        if not self.rec_on:
            return
        op = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
        self.ops.append(op)
        if op == 0x1161:
            k = len(self.sinit)
            if k < 16:
                cells = bytes(uc.mem_read(CELL0 + 0x40 * k, 64))
                s = bytes(cells[4 * i] for i in range(16))
                self.sinit.append(s)
                if k in (0, 1, 3, 7, 15):
                    self.dump(uc, "s1161_%02d" % k)

    # ---------- dumps ----------
    def dump(self, uc, label):
        for lo, sz in DUMP_REGIONS:
            p = os.path.join(HERE, "rec_dump_%s_%s_%s.bin" % (self.tag, label, hex(lo)))
            try:
                open(p, "wb").write(bytes(uc.mem_read(lo, sz)))
                self.dumps_made.append(p)
            except UcError as e:
                print("dump %s %s: UcError %s" % (label, hex(lo), e))
        print("[%s] dumped at %s  t=%.1fs" % (self.tag, label, time.time() - self.t0))


def run_mint(sid):
    cfg = MINTS[sid]
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies[sid]["body_params_dict"])
    emu = RecEmu(cfg["sec"], sid)
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
    out_buf = [None]

    orig_jni = emu.jni_call

    def jni(uc_, idx, x):
        if idx == 208 and x[3] == 304:
            out_buf[0] = x[4]
        return orig_jni(uc_, idx, x)
    emu.jni_call = jni

    try:
        uc.emu_start(base.BASE + 0xA95AC, 0xDEAD0000,
                     timeout=3600 * 1000000, count=3000000000)
    except UcError as e:
        print("[%s] UcError: %s" % (sid, e))

    blob = None
    if out_buf[0] is not None:
        try:
            blob = bytes(uc.mem_read(out_buf[0], 304))
        except UcError:
            pass
    print("[%s] sinit captured: %d, ops: %d" % (sid, len(emu.sinit), len(emu.ops)))
    if blob:
        print("[%s] blob[:32]: %s" % (sid, blob[:32].hex()))
        if cfg["ref"]:
            ref = open(os.path.join(HERE, cfg["ref"])).read().strip()
            print("[%s] blob == %s: %s" % (sid, cfg["ref"], blob.hex() == ref))
        else:
            try:
                ref = json.load(open(os.path.join(
                    WORK, "adj7s4_out7.json")))["out_hex"]
                print("[%s] blob == adj7s4_out7: %s" % (sid, blob.hex() == ref))
            except Exception as e:
                print("[%s] (no ref compare: %s)" % (sid, e))
        open(os.path.join(HERE, "rec_blob_%s.hex" % sid), "w").write(blob.hex())
    json.dump({"sinit": [s.hex() for s in emu.sinit]},
              open(os.path.join(HERE, "rec_sinit_%s.json" % sid), "w"), indent=1)
    print("[%s] dumps: %d files, total t=%.1fs"
          % (sid, len(emu.dumps_made), time.time() - emu.t0))
    return blob is not None


if __name__ == "__main__":
    sids = sys.argv[1:] or ["0015"]
    ok = all(run_mint(s) for s in sids)
    sys.exit(0 if ok else 1)
