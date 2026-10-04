"""Scan ALL of .text: (1) bl -> JNI output wrappers, (2) adrp-based refs to key blobs."""
import os
import sys
import pickle

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF  # noqa: E402
from decryptors import LIB  # noqa: E402

WRAPPERS = {0x9E778: "SetByteArrayRegion", 0x9E54C: "NewByteArray", 0x9AFA4: "?"}
KEY64 = 0x1536D2


def main():
    e = ELF(LIB)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns, callees, imports = pickle.load(open("nsign_cfg.pkl", "rb"))
    inset = set(insns)
    calleeset = set(callees)
    print("is 0x9e778 a known callee? %s ; 0x9e54c? %s" %
          (0x9E778 in calleeset, 0x9E54C in calleeset))

    t = e.byname[".text"]
    lo, hi = t["addr"], t["addr"] + t["size"]
    off0 = e.vaddr_to_off(lo)
    code = e.data[off0:off0 + t["size"]]

    # ---- 1. bl -> wrappers, whole .text
    hits = {v: [] for v in WRAPPERS}
    for i in md.disasm(code, lo):
        if i.mnemonic == "bl" and i.operands and i.operands[0].type == capstone.arm64.ARM64_OP_IMM:
            tgt = i.operands[0].imm
            if tgt in hits:
                hits[tgt].append(i.address)
    for tgt, addrs in hits.items():
        print("\n=== bl -> 0x%x (%s): %d site(s) ===" % (tgt, WRAPPERS[tgt], len(addrs)))
        for a in addrs[:16]:
            onpath = "ON" if a in inset else "off"
            print("  0x%x  [%s]" % (a, onpath))

    # ---- 2. adrp refs (adrp + add  |  adrp + [reg,#off])
    rod = e.byname[".rodata"]
    rlo = rod["addr"]
    targets = {
        KEY64: "64-hex blob (32B hex-decoded?)",
        rlo + 0xC0: ".rodata+0xc0 0123456789abcdeffedcba9876543210",
        rlo + 0xE0: ".rodata+0xe0 f0e1d2c3 9979825a a1ebd96e dcbc1b8f",
        rlo + 0x100: ".rodata+0x100 'SHA-256'",
        rlo + 0x108: ".rodata+0x108 '/system/lib64/libart.so'",
    }
    pages = {}
    for tg, what in targets.items():
        pages.setdefault(tg & ~0xFFF, []).append((tg & 0xFFF, tg, what))

    found = {tg: [] for tg in targets}
    prev = None
    for i in md.disasm(code, lo):
        if i.mnemonic == "adrp" and i.operands and len(i.operands) == 2:
            reg = i.reg_name(i.operands[0].reg)
            imm = i.operands[1].imm
            if imm in pages:
                prev = (reg, imm)
            else:
                prev = None
            continue
        if prev:
            reg, imm = prev
            for moff, tg, what in pages[imm]:
                # add xN, xN, #off
                if i.mnemonic == "add" and i.operands and len(i.operands) == 3 and \
                   i.operands[-1].type == capstone.arm64.ARM64_OP_IMM and \
                   i.operands[-1].imm == moff and i.reg_name(i.operands[0].reg) == reg:
                    found[tg].append(i.address - 4)
                else:
                    # memory operand [xN, #off]
                    for op in i.operands:
                        if op.type == capstone.arm64.ARM64_OP_MEM and \
                           i.reg_name(op.mem.base) == reg and op.mem.disp == moff:
                            found[tg].append(i.address - 4)
                            break
            if i.mnemonic == "adrp":
                continue
            prev = None

    for tg, what in targets.items():
        addrs = found[tg]
        print("\n=== refs to 0x%x  %s : %d ===" % (tg, what, len(addrs)))
        for a in addrs[:24]:
            print("  0x%x  [%s]" % (a, "ON nSign path" if a in inset else "off-path"))


if __name__ == "__main__":
    main()
