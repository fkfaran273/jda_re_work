"""seed_ctx.py - full context of the seeder call: dump fn 0xda980 around 0xdafe4
(+/-80 insns), so we can see: does seeding happen once per nSign (deterministic
for piggyback mints straddling no second) or per mint? Which value feeds it?
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
text = E.byname[".text"]
code = E.data[text["offset"]:text["offset"] + text["size"]]
ins = list(MD.disasm(code, text["addr"]))
pos = {i.address: k for k, i in enumerate(ins)}
k = pos[0xDAFE4]
for i in ins[max(0, k - 80):k + 120]:
    ex = ""
    if i.mnemonic == "bl" and i.operands and i.operands[0].type == 2:
        t = i.operands[0].imm
        ex = "  ; -> %s" % (E.plt_map.get(t) or ("sub_%x" % t))
    mk = "  <<< SEED" if i.address == 0xDAFE4 else ""
    print("  0x%x  %-8s %s%s%s" % (i.address, i.mnemonic, i.op_str, ex, mk))
print("done")
