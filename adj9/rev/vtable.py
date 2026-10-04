"""vtable.py - the vtable calls feeding sub_9afa4: each call site does
ldr x8,[x22]; blr x8,#off (off=0x538/0xf8/0x110/0x108) -> result, then the
result + x22 -> sub_9afa4. x22 = entry x1. Dump x22 origin + the 9c6a4
recursive site.
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

print("=== x22 origin in fn 0xba4a8 (first 40) ===")
for i in ins[pos[0xBA4A8]:pos[0xBA4A8] + 40]:
    print("  0x%x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
print("\n=== 9c6a4 recursive site (20 before) ===")
k = pos[0x9C6A4]
for i in ins[max(0, k - 20):k + 2]:
    print("  0x%x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
print("done")
