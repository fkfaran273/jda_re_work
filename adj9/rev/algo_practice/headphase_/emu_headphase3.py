"""emu_headphase3.py - decisive: snapshot the d0 work buffer at every stage and
dump descriptor #0 exactly as the VM consumes it, then compare each stage
against adj9_pure model d0 for every plausible head phase.

Stage hooks:
  0x1441e4 apply_one entry   (x0=buffer, x1=selector imm)
  0x12d39c serializer        (descriptor plane the VM consumes)
"""
import os, struct, sys, json

HERE = os.path.dirname(os.path.abspath(__file__))
REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR
import emu_8d6f4 as E
import adj9_pure as P
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                 UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                                 UC_ARM64_REG_X6, UC_ARM64_REG_X7,
                                 UC_ARM64_REG_SP, UC_ARM64_REG_PC)

PC_SER = 0x12D39C
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]


def run(n=0):
    cfg = FR.build_cfg(n)
    e = E.Emu(cfg=cfg)
    mu = e.mu
    log = {"applies": [], "d0_snaps": {}, "desc_dump": [], "ser_hits": 0}
    snaps = [0]

    def snap(tag):
        try:
            b = bytes(mu.mem_read(0x300000ffd20, 0x140))
        except Exception as ex:
            b = b"ERR:" + str(ex).encode()
        log["d0_snaps"]["%s#%d" % (tag, snaps[0])] = b.hex()
        snaps[0] += 1

    apply_n = [0]

    def h_apply(uc, address, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        log["applies"].append((apply_n[0], hex(x0), hex(x1 & 0xFF)))
        snap("apply%d_sel%02x" % (apply_n[0], x1 & 0xFF))
        apply_n[0] += 1
    mu.hook_add(UC_HOOK_CODE, h_apply, begin=0x1441E4, end=0x1441E4)

    def h_ser(uc, address, size, ud):
        log["ser_hits"] += 1
        regs = [UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        slots = [uc.reg_read(r) for r in regs]
        sp = uc.reg_read(UC_ARM64_REG_SP)
        for k in range(6):
            try:
                slots.append(struct.unpack("<Q", mu.mem_read(sp + 8 * k, 8))[0])
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
                               "hex": bytes(mu.mem_read(ptr, nb)).hex()})
                else:
                    ds.append({"bi": bi, "nbytes": nb})
            except Exception:
                ds.append({"bi": bi, "nbytes": None})
        log["desc_dump"].append(ds)
        snap("at-ser%d" % log["ser_hits"])
    mu.hook_add(UC_HOOK_CODE, h_ser, begin=PC_SER, end=PC_SER)

    def h_end(uc, address, size, ud):
        snap("at-end")
    mu.hook_add(UC_HOOK_CODE, h_end, begin=0x148A10, end=0x148A10)

    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    blob = e.result.get("blob") or b""
    log["stopped"] = st
    log["blob"] = blob.hex()
    return log, e


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    log, e = run(n)
    json.dump(log, open(os.path.join(HERE, "hp3_trace_%d.json" % n), "w"))
    print("stopped:", log["stopped"], "ser_hits:", log["ser_hits"])
    print("applies:", log["applies"])
    # descriptor #0 as consumed
    d0_desc = None
    for ds in log["desc_dump"]:
        for d in ds:
            if d.get("bi") == 0 and d.get("hex"):
                d0_desc = bytes.fromhex(d["hex"])
                break
        if d0_desc:
            break
    print("desc#0 nbytes:", len(d0_desc or b""))
    if d0_desc:
        print("desc#0[0:48]:", d0_desc[:48].hex())
    # seed from descriptor bi=2 (d2 = LE32(S) stored BE)
    for ds in log["desc_dump"]:
        d2 = next((bytes.fromhex(d["hex"]) for d in ds
                   if d.get("bi") == 2 and d.get("hex")), None)
        if d2:
            seed = struct.unpack("<I", d2[:4])[0]
            break
    print("seed = %08x" % seed)
    # model d0 for every candidate head
    d4 = P._d4_words(seed)
    heads = {"()": (), "(0x2b,)": (0x2b,), "(0x2b,0x48)": (0x2b, 0x48),
             "(0x40,)": (0x40,), "(0x30,)": (0x30,), "(0x22,0x2e)": (0x22, 0x2e),
             "(0x30,0x2b)": (0x30, 0x2b)}
    models = {}
    for name, h in heads.items():
        d0 = P._d0_words(d4, head=h)
        b = b"".join(w.to_bytes(4, "big") for w in d0)
        models[name] = b
    targets = {"desc#0": d0_desc}
    for k, v in log["d0_snaps"].items():
        try:
            targets["snap:" + k] = bytes.fromhex(v)[0x30:0x30 + 144]
        except Exception:
            pass
    for tname, tb in targets.items():
        if not tb:
            continue
        hits = [mn for mn, mb in models.items() if mb == tb[:144]]
        print("%-24s len=%3d match=%s head16=%s" %
              (tname, len(tb), hits or "-", tb[:16].hex()))
    # which snaps differ from the pre-apply state
    keys = list(log["d0_snaps"])
    print("snap count:", len(keys))
