"""seed_callers.py - who calls the srand seeder fn 0x12cb74?
Lists every 'bl 0x12cb74' with enclosing fn (stp scan), plus the 10 prior
instructions, to see how the seeding fits the nSign flow."""
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
outs = []
for i in ins:
    if i.mnemonic == "bl" and i.operands and i.operands[0].type == 2 \
            and i.operands[0].imm == 0x12CB74:
        f = fns[bisect.bisect_right(fns, i.address) - 1]
        outs.append((i.address, f))
print("bl->0x12cb74 sites: %d" % len(outs))
for a, f in outs:
    print("\n--- 0x%x in fn 0x%x ---" % (a, f))
    k = pos[a]
    for i in ins[max(0, k - 10):k + 4]:
        ex = ""
        if i.mnemonic == "bl" and i.operands and i.operands[0].type == 2:
            t = i.operands[0].imm
            ex = "  ; -> %s" % (E.plt_map.get(t) or ("sub_%x" % t))
        print("  0x%x  %-8s %s%s" % (i.address, i.mnemonic, i.op_str, ex))
print("done")
