"""calls9a.py - full call list of sub_9afa4 (0x9afa4..~0x9d000): every bl target
with PLT names, to find WHERE the region buffer comes from (malloc size?
__android_log? fopen/fread of /dev/urandom? gettimeofday?).
Also: adrp/adr targets (data tables?) and mrs (stack canary only?).
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

raw = E.read(0x9AFA4, 0x4000)
ins = list(MD.disasm(raw, 0x9AFA4))
print("decoded %d insns from 0x9afa4" % len(ins))
nret = 0
for i in ins:
    if i.mnemonic == "bl" and i.operands and i.operands[0].type == 2:
        t = i.operands[0].imm
        print("  BL 0x%x -> 0x%x %s" % (i.address, t, E.plt_map.get(t, "")))
    if i.mnemonic in ("adrp", "adr") and len(i.operands) > 1:
        try:
            print("  %s 0x%x -> 0x%x" % (i.mnemonic, i.address, i.operands[1].imm))
        except Exception:
            pass
    if i.mnemonic == "mrs":
        print("  MRS 0x%x %s" % (i.address, i.op_str))
    if i.mnemonic == "ret":
        nret += 1
        if nret >= 2:
            print("  (2nd ret at 0x%x, stop)" % i.address)
            break
print("done")
