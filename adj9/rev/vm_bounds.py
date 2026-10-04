import sys
sys.path.insert(0, '.')
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
# scan 0xf9000..0x101000 for prologues
start, end = 0xf9000, 0x101000
prev = None
for ins in md.disasm(elf[start:end], start):
    op = ins.op_str
    if (ins.mnemonic=="stp" and "x29, x30, [sp, #-" in op) or (ins.mnemonic=="sub" and op.startswith("sp, sp")) or ins.mnemonic=="pacibsp" or (ins.mnemonic=="ret"):
        print("0x%x  %s %s" % (ins.address, ins.mnemonic, op))
