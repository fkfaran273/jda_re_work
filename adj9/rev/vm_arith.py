import sys
sys.path.insert(0, '.')
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
start, end = 0x100000, 0x12aa48
ins_list = list(md.disasm(elf[start:end], start))
ARITH = {"eor","eon","add","adds","sub","subs","madd","msub","mul","and","ands","orr","orn","bic","lsl","lsr","asr","ror","ubfx","sbfx","ubfiz","sbfiz","mvn","neg","negs","sxtw","uxtw","rev","rev16","rev32","rbit","extr","ccmp","csel","csinc","csinv","csneg"}
out = []
for ins in ins_list:
    if ins.mnemonic in ARITH and ins.op_str.startswith("w"):
        out.append("0x%x  %s %s" % (ins.address, ins.mnemonic, ins.op_str))
print(len(out))
for l in out: print(l)
