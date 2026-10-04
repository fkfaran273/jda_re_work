import sys
sys.path.insert(0, '.')
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
start, end = 0x100000, 0x12aa48
ins_list = list(md.disasm(elf[start:end], start))
for i, ins in enumerate(ins_list):
    if ins.mnemonic == "br":
        ctx = ins_list[max(0,i-6):i+1]
        print("BR @0x%x: %s" % (ins.address, " | ".join("%x %s %s" % (c.address,c.mnemonic,c.op_str) for c in ctx)))
# also: who branches TO 0x12a1f8?
tg = {}
for i, ins in enumerate(ins_list):
    if ins.mnemonic in ("b","b.eq","b.ne","cbz","cbnz") and ins.op_str.split(", ")[-1].lstrip("#").startswith("0x"):
        try: t = int(ins.op_str.split(", ")[-1].lstrip("#"), 16)
        except: continue
        tg.setdefault(t, []).append(ins.address)
for a in (0x12a1f8, 0x12a200, 0x12a2f8, 0x12a318, 0x10034c, 0x100354, 0x12a8c0):
    print("target 0x%x <- %s" % (a, ["0x%x"%x for x in tg.get(a, [])][:12]))
