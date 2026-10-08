"""spn_oracle.py — affinity experiments on the chunk-0 SPN via resume oracle.

Reuses spn_resume2.ResumeProbe.  Restores the wc=5.3M snapshot, patches the
chunk-0 input (header IV) with a delta, resumes to just after chunk 0's
final state store, reads the chunk-0 output buffer.

    python spn_oracle.py aff     - affinity test (7 runs)
    python spn_oracle.py basis   - 128 basis runs -> spn_matrix.json
    python spn_oracle.py mix     - patch state at 0x1172 r1 dispatch (n/a yet)
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
from unicorn.arm64_const import *

SEC = 1771238644
SNAP_AT = 5_300_000
STOP_POST = 1_322_200          # just after 0x1183's last store (post-resume wc)
C0_BUF = 0x900F09C


def delta_bytes(iv, e):
    return bytes(a ^ b for a, b in zip(iv, e))


def make_emu():
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])
    emu = sr2.ResumeProbe(SEC)
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
    except base.UcError as e:
        if emu.snap is None:
            print("phase1 UcError:", e)
    if emu.snap is None:
        raise SystemExit("NO SNAPSHOT")
    blob0 = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
    emu.iv_original = blob0[:16]
    emu.ref_c0 = blob0[16:32]
    return emu


def run(emu, e, stop=STOP_POST):
    iv_new = delta_bytes(emu.iv_original, e)
    t = time.time()
    out, _ = emu.run_patched(iv_new, stop_wc=stop)
    print("  e=%s -> %s (%.1fs)" % (e.hex(), out.hex() if out else None,
                                    time.time() - t))
    return out


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "aff"
    emu = make_emu()
    base_out, _ = emu.run_patched(emu.iv_original, stop_wc=STOP_POST)
    print("base chunk0:", base_out.hex())
    print("matches ref :", base_out == emu.ref_c0)
    if mode == "aff":
        tests = []
        for name, e in (("01@0", 1 << 0), ("02@0", 1 << 1), ("03@0", 3),
                        ("80@0", 1 << 7), ("7f@0", 0x7F), ("ff@0", 0xFF),
                        ("01@1", 1 << 8), ("80@15", 1 << 127)):
            tests.append((name, e.to_bytes(16, "big")))
        ds = {}
        for name, e in tests:
            out = run(emu, e)
            ds[name] = bytes(a ^ b for a, b in zip(out, base_out))
        print("\ndiffs:")
        for name, e in tests:
            print("  %-6s %s" % (name, ds[name].hex()))
        ok1 = bytes(a ^ b for a, b in zip(ds["01@0"], ds["02@0"])) == ds["03@0"]
        ok2 = bytes(a ^ b for a, b in zip(ds["80@0"], ds["7f@0"])) == ds["ff@0"]
        ok3 = bytes(a ^ b for a, b in zip(ds["01@0"], ds["02@0"])) == \
            bytes(a ^ b for a, b in zip(ds["01@0"], ds["02@0"]))
        print("\naffinity: d(01)^d(02)==d(03):", ok1,
              " d(80)^d(7f)==d(ff):", ok2)
    elif mode == "basis":
        res = {"base": base_out.hex(), "in": emu.iv_original.hex(),
               "cols": {}}
        for bit in range(128):
            e = (1 << bit)
            ebytes = e.to_bytes(16, "big")
            out = run(emu, ebytes)
            d = bytes(a ^ b for a, b in zip(out, base_out))
            res["cols"][str(bit)] = d.hex()
            if bit % 16 == 15:
                print("  ...bit %d done" % bit)
        with open(os.path.join(HERE, "spn_matrix.json"), "w") as f:
            json.dump(res, f)
        print("saved spn_matrix.json")


if __name__ == "__main__":
    main()
