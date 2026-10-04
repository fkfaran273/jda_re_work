"""r12a.py - the rand call sites sit BELOW the lowest prologue in range: they
belong to a function starting BEFORE 0x128000. Widen the scan to find it,
then dump its full call list + the fate of each rand return (w0).
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

pros = [i.address for i in ins
        if 0x100000 <= i.address < 0x12a300 and i.mnemonic == "stp"
        and "x29" in i.op_str and "x30" in i.op_str]
import bisect
f0 = pros[bisect.bisect_right(pros, 0x12A2FC) - 1]
print("fn(0x12a2fc) = 0x%x" % f0)
# end: next prologue anywhere after f0, or next ret-heavy region; use 0x12aa50
print("next prologue after f0: 0x%x" % min(p for p in
      [i.address for i in ins if i.mnemonic == "stp" and "x29" in i.op_str
       and "x30" in i.op_str and i.address > f0]))
nx = 0x12AA50
k0, k1 = pos[f0], pos[nx]
calls = {}
for i in ins[k0:k1]:
    if i.mnemonic == "bl":
        try:
            t = int(i.op_str.split("#")[1], 16)
        except Exception:
            continue
        calls[t] = calls.get(t, 0) + 1
print("fn size ~0x%x, calls:" % (nx - f0))
for t, c in sorted(calls.items()):
    print("  0x%x x%d %s" % (t, c, E.plt_map.get(t, "")))
# fate of rand returns
for va in (0x12A2FC, 0x12A31C):
    k = pos[va]
    print("--- after bl rand @0x%x ---" % va)
    for i in ins[k + 1:k + 8]:
        print("  0x%x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
print("done")
