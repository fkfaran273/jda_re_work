"""strloop.py - the STRING loop: 0x9b678..0x9b6cc copies bytes one-by-one
(ldrb [x26],#1 ... strb [x11],#1) = strcpy-like. WHICH string? x26=[sp,#0x40]
saved x27, x11=[sp,#0x28] dest. Trace: x27 at entry of sub_9afa4 = ?
sub_9afa4 entry: x19=x1(saved), blr x8 (vtable+0x78 call!). So 9afa4's inputs
are (x0=obj, x1=arg). The 4 call sites in ba4a8 (0xbaa90/0xbac04/0xbb124/
0xbb274) pass different args -> 4 different strings -> 4 different buffers.
Dump those 4 call sites' arg setup (x0/x1 before each bl 0x9afa4).
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

for site in (0xBAA90, 0xBAC04, 0xBB124, 0xBB274):
    print("=== call sub_9afa4 @0x%x (30 before) ===" % site)
    k = pos[site]
    for i in ins[max(0, k - 30):k + 2]:
        print("  0x%x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
print("done")
