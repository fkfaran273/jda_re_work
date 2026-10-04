import sys
sys.path.insert(0, '.')
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
start, end = 0x100000, 0x12aa48
ins_list = list(md.disasm(elf[start:end], start))
for i, ins in enumerate(ins_list):
    if ins.mnemonic == "bl" and "0x147734" in ins.op_str:
        w = ins_list[max(0,i-4):i]
        s = " | ".join("%x %s %s" % (c.address, c.mnemonic, c.op_str) for c in w)
        # pop from control list: ldr x1,[x8] with x8 from [sp,#0x18], or ldr x1,[x20,#0x18]
        if ("ldr      x1, [x8]" in s and any("[sp, #0x18]" in c.op_str and c.mnemonic=="ldr" for c in ins_list[max(0,i-10):i])) \
           or "ldr      x1, [x20, #0x18]" in s:
            print("CTRLPOP @0x%x: %s" % (ins.address, s))
