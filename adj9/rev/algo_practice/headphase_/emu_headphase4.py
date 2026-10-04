"""emu_headphase4.py - who READS the d0 work buffer, and what state do they see?

Hooks UC_HOOK_MEM_READ on the 144-byte d0 fold buffer (0x300000ffd50..e3f),
logs the first N read events with pc + buffer snapshot, and snapshots the
buffer at each apply. Also dumps the serialized descriptor #0 and the final
blob, and compares desc#0 with the pure model for all candidate heads.
"""
import os, struct, sys, json

HERE = os.path.dirname(os.path.abspath(__file__))
REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR
import emu_8d6f4 as E
import adj9_pure as P
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                 UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                                 UC_ARM64_REG_X6, UC_ARM64_REG_X7,
                                 UC_ARM64_REG_SP, UC_ARM64_REG_LR,
                                 UC_ARM64_REG_PC)

D0DATA = 0x300000ffd50  # 144 bytes of d0 halfwords
PC_SER = 0x12D39C
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]


def run(n=0):
    cfg = FR.build_cfg(n)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    log = {"reads": [], "applies": [], "desc_dump": [], "snaps": {}}
    k = [0]
    apply_n = [0]

    def h_read(uc, access, address, size, value, ud):
        if k[0] >= 60:
            return
        pc = uc.reg_read(UC_ARM64_REG_PC)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        try:
            buf = bytes(mu.mem_read(D0DATA, 144))
        except Exception:
            buf = b""
        log["reads"].append({"i": k[0], "pc": hex(pc), "lr": hex(lr),
                             "addr": hex(address), "size": size,
                             "snap": buf.hex()})
        k[0] += 1
    mu.hook_add(UC_HOOK_MEM_READ, h_read, begin=D0DATA,
                end=D0DATA + 143)

    def h_apply(uc, address, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        log["applies"].append({"n": apply_n[0], "x0": hex(x0),
                               "sel": hex(x1 & 0xFF), "lr": hex(lr)})
        try:
            log["snaps"]["apply%d_sel%02x" % (apply_n[0], x1 & 0xFF)] = \
                bytes(mu.mem_read(D0DATA, 144)).hex()
        except Exception:
            pass
        apply_n[0] += 1
    mu.hook_add(UC_HOOK_CODE, h_apply, begin=0x1441E4, end=0x1441E4)

    def h_ser(uc, address, size, ud):
        regs = [UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        slots = [uc.reg_read(r) for r in regs]
        sp = uc.reg_read(UC_ARM64_REG_SP)
        for i in range(6):
            try:
                slots.append(struct.unpack("<Q", mu.mem_read(sp + 8 * i, 8))[0])
            except Exception:
                slots.append(0)
        ds = []
        for va, node in enumerate(slots):
            bi = VA_ORDER[va] if va < len(VA_ORDER) else va
            try:
                nb = struct.unpack("<I", mu.mem_read(node, 4))[0]
                ptr = struct.unpack("<Q", mu.mem_read(node + 8, 8))[0]
                if 0 < nb <= 0x10000 and ptr:
                    ds.append({"bi": bi, "nbytes": nb,
                               "hex": bytes(mu.mem_read(ptr, min(nb, 0x400))).hex(),
                               "ptr": hex(ptr)})
                else:
                    ds.append({"bi": bi, "nbytes": nb})
            except Exception:
                ds.append({"bi": bi, "nbytes": None})
        log["desc_dump"].append(ds)
    mu.hook_add(UC_HOOK_CODE, h_ser, begin=PC_SER, end=PC_SER)

    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    blob = e.result.get("blob") or b""
    log["stopped"] = st
    log["blob"] = blob.hex()
    return log, e


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    log, e = run(n)
    json.dump(log, open(os.path.join(HERE, "hp4_trace_%d.json" % n), "w"))
    print("stopped:", log["stopped"])
    print("n read events captured:", len(log["reads"]))
    for r in log["reads"][:20]:
        print("read i=%d pc=%s lr=%s addr=%s sz=%d head16=%s" %
              (r["i"], r["pc"], r["lr"], r["addr"], r["size"],
               r["snap"][:32] if r["snap"] else "-"))
    print("applies:", [(a["n"], a["sel"], a["lr"]) for a in log["applies"]])
    d0_desc = None
    for ds in log["desc_dump"]:
        for d in ds:
            if d.get("bi") == 0 and d.get("hex"):
                d0_desc = bytes.fromhex(d["hex"]); d0_ptr = d.get("ptr")
                break
        if d0_desc: break
    print("desc#0 ptr:", d0_ptr, "head16:", d0_desc[:16].hex() if d0_desc else None)
    # seed from desc bi=2
    for ds in log["desc_dump"]:
        d2 = next((bytes.fromhex(d["hex"]) for d in ds
                   if d.get("bi") == 2 and d.get("hex")), None)
        if d2:
            seed = struct.unpack("<I", d2[:4])[0]; break
    print("seed=%08x" % seed)
    d4 = P._d4_words(seed)
    models = {}
    for name, h in {"()": (), "(0x2b,)": (0x2b,), "(0x2b,0x48)": (0x2b, 0x48),
                    "(0x40,)": (0x40,), "(0x30,)": (0x30,),
                    "(0x30,0x2b)": (0x30, 0x2b)}.items():
        models[name] = b"".join(w.to_bytes(4, "big")
                                for w in P._d0_words(d4, head=h))
    if d0_desc:
        hits = [mn for mn, mb in models.items() if mb == d0_desc[:144]]
        print("desc#0 model match:", hits or "-")
        # halfword diff vs each model
        for mn, mb in models.items():
            diff = [i for i in range(72)
                    if mb[2 * i:2 * i + 2] != d0_desc[2 * i:2 * i + 2]]
            print("  vs %-10s diff slots: %s" % (mn, diff[:16]))
