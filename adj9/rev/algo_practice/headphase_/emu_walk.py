"""emu_walk.py - fold-site walk under different inputs.

usage: python emu_walk.py ROW [urandom8_hex]
Hooks every direct `bl 0x1441e4` site found statically; logs w1 at each.
"""
import os, struct, sys, json

HERE = os.path.dirname(os.path.abspath(__file__))
REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR
import emu_8d6f4 as E
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_SP

# every direct bl 0x1441e4 site found by the raw scan (pc -> expected imm)
SITES = {0x8c48: 0x2b, 0x8c7c: 0x39, 0xdb14: 0x9, 0xde08: 0x34, 0xe20c: 0x29,
         0xe38c: 0x37, 0xeba0: 0x2a, 0xee58: 0x38, 0xf620: 0x7, 0xf998: 0x33,
         0xfaa0: 0x5, 0xffb8: 0x28, 0xffe4: 0x2c, 0x10010: 0x8, 0x10064: 0x1e,
         0x10090: 0x20, 0x1014c: 0x3, 0x10178: 0x1f, 0x10218: 0x2,
         0x10330: 0x27, 0x1038c: 0x1, 0x136b4: 0x21, 0x14410: 0x4,
         0x14714: 0xa, 0x14818: 0x32, 0x1484c: 0x32, 0x14d70: 0x25,
         0x14df4: 0x2d, 0x14e7c: 0x2e, 0x14fa8: 0x22, 0x150d0: 0x23,
         0x152b4: 0x35, 0x152e8: 0x36, 0x1531c: 0x3a, 0x15350: 0x3a,
         0x15498: 0x2f, 0x1555c: 0x3b, 0x1682c: 0x3c, 0x1b550: 0x48,
         0x1b6c8: 0x4a, 0x1b8a0: 0x49, 0x973a8: 0x30, 0xe4b30: 0x26}


def run(n, urandom8=None):
    cfg = FR.build_cfg(n)
    if urandom8:
        cfg["urandom8"] = bytes.fromhex(urandom8)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    log = {"folds": [], "stack": None, "mismatch": []}

    for site, imm in SITES.items():
        def mk(s, im):
            def h(uc, address, size, ud):
                w1 = uc.reg_read(UC_ARM64_REG_X1) & 0xFF
                rec = {"site": hex(s), "w1": hex(w1)}
                if w1 != im:
                    rec["expected"] = hex(im)
                    log["mismatch"].append(rec)
                if log["stack"] is None:
                    sp = uc.reg_read(UC_ARM64_REG_SP)
                    fr = []
                    try:
                        mem = bytes(mu.mem_read(sp, 0x500))
                        for k in range(0, 0x500, 8):
                            v = struct.unpack_from("<Q", mem, k)[0]
                            if 0x9000 <= v < 0x149000 and v > 0x10000:
                                fr.append(hex(v))
                    except Exception:
                        pass
                    rec["stack"] = fr[:28]
                    log["stack"] = rec["stack"]
                log["folds"].append(rec)
            return h
        mu.hook_add(UC_HOOK_CODE, mk(site, imm), begin=site, end=site)

    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    blob = e.result.get("blob") or b""
    log["stopped"] = st
    log["blob16"] = blob[:16].hex()
    return log, e


if __name__ == "__main__":
    n = int(sys.argv[1])
    ur = sys.argv[2] if len(sys.argv) > 2 else None
    log, e = run(n, ur)
    print("row %d urandom8=%s stopped=%s blob16=%s" %
          (n, ur, log["stopped"], log["blob16"]))
    print("fold walk (%d folds):" % len(log["folds"]))
    print("  " + " -> ".join(f["w1"] for f in log["folds"]))
    if log["mismatch"]:
        print("MISMATCHES:", log["mismatch"])
    print("first-fold stack:", log["stack"])
    json.dump(log, open(os.path.join(HERE, "walk_%d_%s.json" % (n, ur or "emu")), "w"))
