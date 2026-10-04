"""ba4a8_flow.py - control flow of the TRUE region-builder entry 0xba4a8:
which sub-functions run, where the dispatch hub is, and whether rand/time/
gettimeofday appear anywhere in ITS tree (they don't appear in its own 6
calls: only free/sub_9afa4/sub_1483e0). Recursively expand sub_9afa4 and
sub_1483e0 one level to find where #0/#2/#4 bytes are actually produced.
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


def calls_of(entry, cap=0x2000):
    raw = E.read(entry, cap)
    out = []
    for ins in MD.disasm(raw, entry):
        if ins.mnemonic == "ret":
            break
        if ins.mnemonic == "bl" and ins.operands and ins.operands[0].type == 2:
            t = ins.operands[0].imm
            out.append((ins.address, t, E.plt_map.get(t, "")))
    return out


for entry in (0x9AFA4, 0x1483E0):
    cs = calls_of(entry)
    print("=== calls of sub_%x (%d) ===" % (entry, len(cs)))
    for a, t, nm in cs[:40]:
        print("  0x%x -> 0x%x %s" % (a, t, nm or ("sub_%x" % t)))
print("done")
