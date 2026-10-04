# text_scan.py - find the biggest RX segment, then locate the two .bss arrays the
# VM walks (the merged-sink + merge offset grid) by scanning every BL target and
# mapping ADRP references of .bss across .text. Reports candidate VA-table bases
# used by the FinEx emulator + WH4 ground truth.
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
E = ELF(SO)
print("sections:", sorted(E.byname.keys())[:14], "...")
for sn in (".text", ".rodata", ".data.rel.ro", ".data", ".bss"):
    s = E.byname.get(sn)
    if s:
        print("  %-14s va=0x%-8x off=0x%-8x size=0x%x" % (sn, s["addr"], s["offset"], s["size"]))

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
t = E.byname[".text"]
code = E.data[t["offset"]:t["offset"] + t["size"]]
n_bl = n_adrp = 0
bss_refs = []
for ins in md.disasm(code, t["addr"]):
    if ins.mnemonic == "bl":
        n_bl += 1
    if ins.mnemonic == "adrp" and ins.operands and ins.operands[1].type == 2:
        n_adrp += 1
        imm = ins.operands[1].imm
        page = (ins.address & ~0xFFF) + imm
        b = E.byname.get(".bss")
        if b and b["addr"] <= page < b["addr"] + b["size"]:
            bss_refs.append((ins.address, page))
print("bl=%d adrp=%d bss_refs=%d" % (n_bl, n_adrp, len(bss_refs)))
for a, p in bss_refs[:30]:
    print("  0x%x -> bss page 0x%x" % (a, p))
print("done")