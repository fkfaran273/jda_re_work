# r3_scan.py - the 0x148980-family tail: which imports each member touches.
# OP_RAND (=0x148d10, the rand() PLT) sits in this family; the srand(0x12cbc0)
# sibling decides the seed image. Print the nearest imported-call cluster per
# 0x100-aligned member window in 0x147f90..0x148f90.
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
pos = {i.address: i for i in ins}
base = 0x147F90
for w in range(base, base + 0x1000, 0x100):
    found = []
    for i in ins:
        if w <= i.address < w + 0x100 and i.mnemonic == "bl" and i.operands \
                and i.operands[0].type == 2:
            t = i.operands[0].imm
            found.append((i.address, E.plt_map.get(t) or ("sub_%x" % t)))
    if [f for _, f in found if f in ("rand", "srand", "malloc", "calloc", "free",
                                     "clock_gettime", "gettimeofday", "fopen",
                                     "fread", "time")]:
        print("--- window 0x%x ---" % w)
        for a, f in found:
            print("  0x%x -> %s" % (a, f))
print("done")