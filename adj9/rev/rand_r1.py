# rand_r1.py - the two rand() call sites at 0x12a2fc / 0x12a31c: function context,
# which results feed the per-call region, and whether rand() output is consumed
# inline (the W/C triad) or through the VM emit lane.
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
E = ELF(SO)
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True
text = E.byname[".text"]
code = E.data[text["offset"]:text["offset"] + text["size"]]
ins = list(MD.disasm(code, text["addr"]))
pos = {i.address: k for k, i in enumerate(ins)}
for va in (0x12A2FC, 0x12A31C):
    print("=== 60 insns before bl rand @0x%x ===" % va)
    k = pos[va]
    for i in ins[max(0, k - 60):k + 26]:
        ex = ""
        if i.mnemonic == "bl" and i.operands and i.operands[0].type == 2:
            t = i.operands[0].imm
            ex = "  ; -> %s" % (E.plt_map.get(t) or ("sub_%x" % t))
        print("  0x%x  %-8s %s%s" % (i.address, i.mnemonic, i.op_str, ex))
print("done")