"""Chase (a) callers of the JNI SetByteArrayRegion wrapper 0x9e778,
(b) code references to the 64-hex blob @0x1536d2 and the .rodata constants.
"""
import os
import sys
import pickle

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF  # noqa: E402
from decryptors import LIB  # noqa: E402

WRAP = 0x9E778
NBA = 0x9E54C


def dis(e, md, va, n):
    off = e.vaddr_to_off(va)
    return list(md.disasm(e.data[off:off + n * 4], va))


def main():
    e = ELF(LIB)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns, callees, imports = pickle.load(open("nsign_cfg.pkl", "rb"))
    inset = set(insns)

    # ---- 1. callers of the two wrappers
    for tgt, label in ((WRAP, "SetByteArrayRegion wrapper"), (NBA, "NewByteArray wrapper")):
        hits = []
        for a in sorted(inset):
            if not (0x10000 < a < 0x150000):
                continue
            try:
                i = dis(e, md, a, 1)[0]
            except Exception:
                continue
            if i.mnemonic == "bl" and i.operands and i.operands[0].imm == tgt:
                hits.append(a)
        print("\n=== callers of %s (0x%x) on nSign path: %d ===" % (label, tgt, len(hits)))
        for a in hits[:20]:
            print("  ---- @0x%x" % a)
            for i in dis(e, md, a - 48, 16):
                mark = "  <<<" if i.address == a else ""
                extra = ""
                if "#0xc0" in i.op_str or "#192" in i.op_str:
                    extra = "   <== 192!"
                if i.mnemonic == "bl":
                    extra += "  (call 0x%x)" % i.operands[0].imm
                print("    0x%x: %-8s %s%s%s" % (i.address, i.mnemonic, i.op_str, extra, mark))

    # ---- 2. references to the 64-hex string and .rodata
    text = e.byname[".text"]
    lo, hi = text["addr"], text["addr"] + text["size"]
    rod = e.byname[".rodata"]
    rlo, rhi = rod["addr"], rod["addr"] + rod["size"]
    print("\n.rodata @ 0x%x size 0x%x" % (rlo, rod["size"]))

    targets = {
        0x1536D2: "64-hex blob (32 bytes if hex-decoded)",
        rlo + 0xC0: ".rodata+0xc0  0123456789abcdef fedcba9876543210",
        rlo + 0xE0: ".rodata+0xe0  f0e1d2c3 9979825a a1ebd96e dcbc1b8f",
        rlo + 0x100: ".rodata+0x100 'SHA-256'",
    }

    for t, what in targets.items():
        page = t & ~0xFFF
        off = t & 0xFFF
        print("\n=== refs to 0x%x  %s ===" % (t, what))
        found = 0
        for a in range(lo, hi, 4):
            try:
                i = dis(e, md, a, 1)[0]
            except Exception:
                continue
            if i.mnemonic == "adrp" and i.operands and i.operands[0].type == capstone.arm64.ARM64_OP_REG:
                imm = i.operands[1].imm
                if imm == page:
                    nxt = dis(e, md, a + 4, 1)[0]
                    if nxt.mnemonic == "add" and nxt.operands and \
                       nxt.operands[-1].type == capstone.arm64.ARM64_OP_IMM and \
                       nxt.operands[-1].imm == off:
                        onpath = "ON nSign path" if a in inset else "off-path"
                        print("  0x%x  %s %s | %s %s   [%s]" %
                              (a, i.mnemonic, i.op_str, nxt.mnemonic, nxt.op_str, onpath))
                        found += 1
                        if found > 24:
                            print("  ...")
                            break
        if not found:
            print("  (none)")


if __name__ == "__main__":
    main()
