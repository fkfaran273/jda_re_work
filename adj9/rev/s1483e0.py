"""s1483e0.py - what is sub_1483e0? Zero calls: a leaf. Dump its body: if it is
a crypto/compression primitive (AES/SHA constants?) that shapes #0/#2/#4,
its immediates give the construction away. Also dump 0x956e4's call list
(the OTHER true entry, sibling of the region path)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF

SO = r"C:\Users\\Apps\\Downloads\\com.penti.app\\extracted\\arm64\\lib\\arm64-v8a\\libsigner.so"
SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
E = ELF(SO)
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True

raw = E.read(0x1483E0, 0x800)
ins = list(MD.disasm(raw, 0x1483E0))
print("sub_1483e0: %d insns to first ret" % len(ins))
n = 0
for i in ins:
    print("  0x%x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
    n += 1
    if i.mnemonic == "ret" or n > 60:
        break
print("done")
