import sys
sys.path.insert(0, '.')
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
size = len(elf)
print("lib size 0x%x" % size)
# 1) prologues in 0x128000..0x12a200
start, end = 0x128000, 0x12a200
for ins in md.disasm(elf[start:end], start):
    op = ins.op_str
    if (ins.mnemonic=="stp" and "x29, x30, [sp, #-" in op) or (ins.mnemonic=="sub" and op.startswith("sp, sp")) or ins.mnemonic=="pacibsp":
        print("PRO 0x%x  %s %s" % (ins.address, ins.mnemonic, op))
