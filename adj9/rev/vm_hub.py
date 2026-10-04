import sys
sys.path.insert(0, '.')
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
start, end = 0x100000, 0x12aa48
ins_list = list(md.disasm(elf[start:end], start))
from collections import Counter
cseq = 0
for i, ins in enumerate(ins_list):
    if ins.mnemonic == "cmp":
        cseq += 1
    else:
        if cseq >= 8:
            print("cmp-chain of %d ending @0x%x (%s %s)" % (cseq, ins_list[i-1].address, ins_list[i-1].mnemonic, ins_list[i-1].op_str))
        cseq = 0
