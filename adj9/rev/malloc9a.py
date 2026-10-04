"""malloc9a.py - the malloc at 0x9b6e4 inside sub_9afa4: what size? Trace w0/x0
backwards from the call: the allocation size = the region buffer size DIRECTLY
(#0 144? #4 32? #0+#4+headers?). Dump 40 insns before the malloc.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
E = ELF(SO)
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
text = E.byname[".text"]
code = E.data[text["offset"]:text["offset"] + text["size"]]
ins = list(MD.disasm(code, text["addr"]))
pos = {i.address: k for k, i in enumerate(ins)}
k = pos[0x9B6E4]
for i in ins[max(0, k - 30):k + 4]:
    print("  0x%x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
print("done")
