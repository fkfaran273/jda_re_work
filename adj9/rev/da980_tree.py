"""da980_tree.py - what is fn 0xda980 (the seeder's caller) and how does it relate
to nSign 0xdb1cc? Callers of 0xda980, callees around seed, and whether the two
rand() draws at 0x12a2fc/0x12a31c are reached from the same tree."""
import os
import sys
import bisect

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
E = ELF(SO)
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True
text = E.byname[".text"]
code = E.data[text["offset"]:text["offset"] + text["size"]]
ins = list(MD.disasm(code, text["addr"]))
pos = {i.address: k for k, i in enumerate(ins)}
fns = [i.address for i in ins
       if i.mnemonic == "stp" and "x29" in i.op_str and "x30" in i.op_str]

for target in (0xDA980, 0xDB1CC):
    callers = [(i.address, fns[bisect.bisect_right(fns, i.address) - 1])
               for i in ins if i.mnemonic == "bl" and i.operands
               and i.operands[0].type == 2 and i.operands[0].imm == target]
    print("callers of 0x%x: %d" % (target, len(callers)))
    for a, f in callers[:20]:
        print("  0x%x in fn 0x%x" % (a, f))

# where does 0xda980 start/end (stp scan), and does it call nSign 0xdb1cc?
s = fns[bisect.bisect_right(fns, 0xDA980) - 1]
print("\nfn(0xda980) = 0x%x" % s)
k0, k1 = pos[s], pos[0xDB1CC]
inner = [i for i in ins[k0:k0 + 3000]
         if i.mnemonic == "bl" and i.operands and i.operands[0].type == 2]
print("bl targets in fn 0xda980 (first 40):")
for i in inner[:40]:
    t = i.operands[0].imm
    print("  0x%x -> %s" % (i.address, E.plt_map.get(t) or ("sub_%x" % t)))
print("done")
