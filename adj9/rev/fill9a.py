"""fill9a.py - the malloc'd buffer fill inside sub_9afa4: after malloc at
0x9b6e4 (size = strlen+1 of a string arg!), where do the malloc'd bytes go?
Trace the malloc return (x0) forward: strb copy loop at 0x9b694..0x9b6cc
copies a STRING byte-by-byte. Which string? (x9=[sp,#0x20] source pointer.)
The region buffers may be string-derived (map strings!) -> #0/#2/#4 could be
TRANSFORMS of map strings, not random at all.

Dump 0x9b6d0..0x9b900 fully.
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
for i in ins[pos[0x9B6D0]:pos[0x9B900]]:
    print("  0x%x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
print("done")
