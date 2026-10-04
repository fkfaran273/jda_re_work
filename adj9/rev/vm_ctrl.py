import sys
sys.path.insert(0, '.')
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
start, end = 0x100000, 0x12aa48
ins_list = list(md.disasm(elf[start:end], start))
n = len(ins_list)
for i, ins in enumerate(ins_list):
    if ins.mnemonic == "bl" and "0x147734" in ins.op_str:
        ctx = ins_list[max(0,i-6):i]
        s = " | ".join("%x %s %s" % (c.address, c.mnemonic, c.op_str) for c in ctx)
        if "#0x18]" in s:
            print("CTRLPOP @0x%x: %s" % (ins.address, s))
