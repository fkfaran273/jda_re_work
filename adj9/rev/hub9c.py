"""hub9c.py - dump the 0x9c580 dispatch hub (the loop cluster in sub_9afa4):
the hub at 0x9b168-style dispatches; 0x9c580 has 8+ tight loops. Dump
0x9c500..0x9c700 fully: which arm writes the 16B tile (stp q?), trip counts,
and where W0/W1/C-triads come from (registers carrying map data? time?).
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

for lo, hi in ((0x9C500, 0x9C700), (0xBA600, 0xBA800)):
    print("=== 0x%x..0x%x ===" % (lo, hi))
    for i in ins[pos[lo]:pos[hi]]:
        print("  0x%x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
print("done")
