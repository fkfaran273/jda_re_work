"""Disassemble the REAL nSign body (dynsym 0xdb1cc, size 0xc74) and hunt the
descriptor construction: buffer fills sized 144 (#0), 32 (#4), 4 (#2), 90 (#10),
plus entropy sources (gettimeofday/clock_gettime/getrandom/rand/malloc) and
stack-pointer-derived stores (the MTE-pointer hypothesis for #0)."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nsign_body.log")

E = ELF(SO)
START, SIZE = 0xDB1CC, 0xC74
code = E.read(START, SIZE)
assert code and len(code) == SIZE, "nSign body unreadable"

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
lines, bls, adrs = [], [], []
for ins in md.disasm(code, START):
    extra = ""
    if ins.mnemonic == "bl" and ins.operands and ins.operands[0].type == 2:
        tgt = ins.operands[0].imm
        extra = "   ; -> 0x%x%s" % (tgt, " [PLT]" if tgt in E.plt_map else "")
        bls.append((ins.address, tgt, E.plt_map.get(tgt, "")))
    if ins.mnemonic in ("adrp", "adr"):
        adrs.append((ins.address, ins.mnemonic, ins.op_str))
    lines.append("0x%x  %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, extra))

imp = {}
for a, t, name in bls:
    imp.setdefault(name or ("sub_%x" % t), []).append(a)

with open(OUT, "w") as f:
    f.write("nSign 0x%x size 0x%x : %d insns\n" % (START, SIZE, len(lines)))
    f.write("== PLT/import calls ==\n")
    for k in sorted(imp):
        f.write("  %-28s x%d  e.g. %s\n" % (k, len(imp[k]),
                                            ", ".join("0x%x" % a for a in imp[k][:6])))
    f.write("== adrp/adr ==\n")
    for a, m, o in adrs:
        f.write("  0x%x  %-4s %s\n" % (a, m, o))
    f.write("== full body ==\n")
    f.write("\n".join(lines) + "\n")
print("insns=%d bl=%d adrp/adr=%d" % (len(lines), len(bls), len(adrs)))
print("imports:", sorted(imp.keys()))
print("saved %s" % OUT)
