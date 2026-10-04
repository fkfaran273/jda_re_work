import sys
sys.path.insert(0, '.')
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
start, end = 0x100000, 0x12aa48
ins_list = list(md.disasm(elf[start:end], start))
print("decoded %d insns" % len(ins_list))
# find: ldr x8, [sp, #0x18] ... bl 0x147734 (pop from control list)
for i, ins in enumerate(ins_list):
    if ins.mnemonic == "bl" and "0x147734" in ins.op_str:
        # look back 8 for 'ldr x8, [sp, #0x18]' or similar control list load
        ctx = ins_list[max(0,i-8):i]
        s = " | ".join("%x %s %s" % (c.address, c.mnemonic, c.op_str) for c in ctx)
        if "[sp, #0x18]" in s and "x8" in s:
            # then look ahead for cmp chain
            nxt = ins_list[i+1:i+6]
            s2 = " | ".join("%x %s %s" % (c.address, c.mnemonic, c.op_str) for c in nxt)
            if "cmp" in s2:
                print("DISPATCH-POP @0x%x: %s || NEXT: %s" % (ins.address, s[-160:], s2[:160]))
