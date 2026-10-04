"""s9afa4.py - dump sub_9afa4's full body (the region shaper called 4x from the
0xba4a8 tree): immediates, adrp targets, and the straight-line structure.
It calls malloc once + sub_1483e0 (atomic latch) 3x. The malloc SIZE + the
write pattern after it reveal the region buffer layout (#0 144B? #4 32B?).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
E = ELF(SO)
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True

raw = E.read(0x9AFA4, 0x3000)
ins = list(MD.disasm(raw, 0x9AFA4))
print("sub_9afa4: %d insns decoded" % len(ins))
for i in ins[:220]:
    ex = ""
    if i.mnemonic == "bl" and i.operands and i.operands[0].type == 2:
        t = i.operands[0].imm
        ex = "  ; -> %s" % (E.plt_map.get(t) or ("sub_%x" % t))
    print("  0x%x  %-8s %s%s" % (i.address, i.mnemonic, i.op_str, ex))
    if i.mnemonic == "ret":
        break
print("done")
