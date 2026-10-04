"""emu_headphase5.py - who reads the encrypted-string/phase area (0x1551c0-0x155229)
during the fold walk; what do the strings decode to; checker 0x39c1c args/results.
"""
import os, struct, sys, json

HERE = os.path.dirname(os.path.abspath(__file__))
REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR
import emu_8d6f4 as E
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_X2, UC_ARM64_REG_PC,
                                 UC_ARM64_REG_LR)

SITES = {0x8c30: 0x2b, 0x97390: 0x30, 0xddf0: 0x34, 0xe374: 0x37,
         0xee40: 0x38, 0x15544: 0x3b, 0x1529c: 0x35, 0x152d0: 0x36,
         0x14dec: 0x2d, 0xfa98: 0x05}


def run(n=0):
    cfg = FR.build_cfg(n)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    log = {"reads": [], "folds": [], "checker": []}
    seen_reads = [0]

    def h_read(uc, access, address, size, value, ud):
        if seen_reads[0] > 400:
            return
        pc = uc.reg_read(UC_ARM64_REG_PC)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        try:
            ctxb = bytes(mu.mem_read(address & ~7, 0x20))
        except Exception:
            ctxb = b""
        log["reads"].append({"pc": hex(pc), "lr": hex(lr),
                             "addr": hex(address), "sz": size,
                             "ctx": ctxb.hex()})
        seen_reads[0] += 1
    mu.hook_add(UC_HOOK_MEM_READ, h_read, begin=0x1551c0, end=0x155229)

    for site in SITES:
        def mk(s):
            def h(uc, address, size, ud):
                log["folds"].append({"site": hex(s), "imm": hex(SITES[s]),
                                     "lr": hex(uc.reg_read(UC_ARM64_REG_LR)),
                                     "x0": hex(uc.reg_read(UC_ARM64_REG_X0))})
            return h
        mu.hook_add(UC_HOOK_CODE, mk(site), begin=site, end=site)

    def h_chk(uc, address, size, ud):
        log["checker"].append({"entry": True,
                               "x0": hex(uc.reg_read(UC_ARM64_REG_X0)),
                               "x1": hex(uc.reg_read(UC_ARM64_REG_X1)),
                               "x2": hex(uc.reg_read(UC_ARM64_REG_X2)),
                               "x3": hex(uc.reg_read(UC_ARM64_REG_X3))})
    mu.hook_add(UC_HOOK_CODE, h_chk, begin=0x39c1c, end=0x39c1c)

    def h_chkret(uc, address, size, ud):
        log["checker"].append({"ret_pc": hex(address),
                               "w0": uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF})
    mu.hook_add(UC_HOOK_CODE, h_chkret, begin=0x14744, end=0x14744)

    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    log["stopped"] = st
    try:
        log["decoded"] = bytes(mu.mem_read(0x1551c0, 0x6a)).hex()
    except Exception:
        pass
    try:
        log["phase_final"] = bytes(mu.mem_read(0x155228, 2)).hex()
    except Exception:
        pass
    blob = e.result.get("blob") or b""
    log["blob"] = blob.hex()
    return log, e


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    log, e = run(n)
    json.dump(log, open(os.path.join(HERE, "hp5_trace_%d.json" % n), "w"))
    print("stopped:", log.get("stopped"))
    print("phase_final:", log.get("phase_final"))
    dec = bytes.fromhex(log.get("decoded", ""))
    print("decoded strings region:")
    print(" ", dec[:0x40].hex(" "))
    print("  ascii:", "".join(chr(c) if 32 <= c < 127 else "." for c in dec))
    print("folds:", [(f["site"], f["imm"]) for f in log["folds"]])
    print("checker events:", len(log["checker"]))
    for c in log["checker"][:10]:
        print("  ", c)
    print("reads of string/phase area:", len(log["reads"]))
    for r in log["reads"][:30]:
        print("  pc=%s lr=%s addr=%s sz=%d" % (r["pc"], r["lr"], r["addr"], r["sz"]))
