"""_emu_probe.py - instrumented end-to-end signing run: hooks the wire-builder
STORE sites (0x146ed8 EMIT, 0x147630 PUSH), the 16-bit whitener (0x14418c) and
the serializer (0x12d39c, descriptor dump); dumps everything for offline
classification.  Usage: python _emu_probe.py TAG [cfg_json_override]"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import full_replay as FR
import emu_8d6f4 as E
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                 UC_ARM64_REG_X11, UC_ARM64_REG_X19,
                                 UC_ARM64_REG_LR, UC_ARM64_REG_SP,
                                 UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                                 UC_ARM64_REG_X6, UC_ARM64_REG_X7)

VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
PC_EMIT, PC_PUSH, PC_WHITE, PC_SER = 0x146ED8, 0x147630, 0x14418C, 0x12D39C


def run_probe(tag, over=None, n=0):
    cfg = FR.build_cfg(n)
    if over:
        cfg.update(over)
    e = E.Emu(cfg=cfg)
    emit_log, push_log, white_log = [], [], []
    desc_dump = {}

    def hook_emit(uc, address, size, ud):
        emit_log.append((len(emit_log),
                         uc.reg_read(UC_ARM64_REG_X1),
                         uc.reg_read(UC_ARM64_REG_X2),
                         uc.reg_read(UC_ARM64_REG_X3),
                         uc.reg_read(UC_ARM64_REG_LR)))

    def hook_push(uc, address, size, ud):
        push_log.append((len(push_log),
                         uc.reg_read(UC_ARM64_REG_X1),
                         uc.reg_read(UC_ARM64_REG_X2),
                         uc.reg_read(UC_ARM64_REG_LR)))

    def hook_white(uc, address, size, ud):
        pa = uc.reg_read(UC_ARM64_REG_X19)
        try:
            pre = struct.unpack("<H", uc.mem_read(pa, 2))[0]
        except Exception:
            pre = -1
        white_log.append((len(white_log), pa, pre,
                          uc.reg_read(UC_ARM64_REG_X2) & 0xFFFF,
                          uc.reg_read(UC_ARM64_REG_X11)))

    def hook_ser(uc, address, size, ud):
        regs = [UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        slots = [uc.reg_read(r) for r in regs]
        sp = uc.reg_read(UC_ARM64_REG_SP)
        for k in range(6):
            try:
                slots.append(struct.unpack("<Q", uc.mem_read(sp + 8 * k, 8))[0])
            except Exception:
                slots.append(0)
        ds = []
        mu = e.mu
        for va, node in enumerate(slots):
            bi = VA_ORDER[va] if va < len(VA_ORDER) else va
            try:
                nb = struct.unpack("<I", mu.mem_read(node, 4))[0]
                ptr = struct.unpack("<Q", mu.mem_read(node + 8, 8))[0]
                if 0 < nb <= 0x10000 and ptr:
                    ds.append({"va": va, "bi": bi, "nbytes": nb,
                               "hex": bytes(mu.mem_read(ptr, nb)).hex()})
                else:
                    ds.append({"va": va, "bi": bi, "nbytes": nb})
            except Exception:
                ds.append({"va": va, "bi": bi, "nbytes": None})
        desc_dump[("hit%d" % len(desc_dump))] = ds

    e.mu.hook_add(UC_HOOK_CODE, hook_emit, begin=PC_EMIT, end=PC_EMIT)
    e.mu.hook_add(UC_HOOK_CODE, hook_push, begin=PC_PUSH, end=PC_PUSH)
    e.mu.hook_add(UC_HOOK_CODE, hook_white, begin=PC_WHITE, end=PC_WHITE)
    e.mu.hook_add(UC_HOOK_CODE, hook_ser, begin=PC_SER, end=PC_SER)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    blob = e.result.get("blob") or b""
    out = {"tag": tag, "stopped": st, "blob": blob.hex(),
           "srand": e.srand_log,
           "rand": [(i, v, hex(lr)) for i, v, lr in e.rand_calls],
           "n_emit": len(emit_log), "n_push": len(push_log),
           "n_white": len(white_log),
           "descs": desc_dump,
           "emit_tail": emit_log[-40000:],
           "white_tail": white_log[-40000:],
           "push_tail": push_log[-20000:]}
    json.dump(out, open(os.path.join(HERE, "_emu_probe_%s.json" % tag), "w"))
    print("PROBE %s: %s blob_len=%d emits=%d pushes=%d white=%d ser_hits=%d"
          % (tag, st, len(blob), len(emit_log), len(push_log), len(white_log),
             len(desc_dump)))
    return out


if __name__ == "__main__":
    tag = sys.argv[1]
    over = json.loads(sys.argv[2]) if len(sys.argv) > 2 else None
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    run_probe(tag, over, n)
