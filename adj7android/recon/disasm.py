# Fresh capstone disassembler for libsigner.so with bl/adrp annotation
import sys, struct
from capstone import *
from capstone.arm64 import *

d = open(r"..\apks\lib\hanaf\libsigner.so", "rb").read()
TEXT_ADDR = 0xa090
TEXT_OFF = 0xa090
TEXT_END = TEXT_ADDR + 0x108c3c

def off2va(off):
    return TEXT_ADDR + (off - TEXT_OFF)

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

def disasm_range(start_va, size, label=""):
    print("==== %s @ %x (+%x) ====" % (label, start_va, size))
    code = d[start_va - TEXT_ADDR + TEXT_OFF: start_va - TEXT_ADDR + TEXT_OFF + size]
    for ins in md.disasm(code, start_va):
        note = ""
        if ins.mnemonic in ("bl", "b") and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            tgt = ins.operands[0].imm
            note = "  ; -> %x" % tgt
        if ins.mnemonic == "bl":
            for r in ins.regs_read:
                pass
        print("  %08x  %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, note))

if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "nsign"
    if what == "nsign":
        disasm_range(0xa95ac, 0xd94, "Java_..._nSign")
    elif what.startswith("0x"):
        va = int(what, 16)
        sz = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x100
        disasm_range(va, sz, "sub_%x" % va)
