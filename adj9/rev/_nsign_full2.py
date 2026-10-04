from capstone import *
elf=open("../split_config.arm64_v8a/lib/arm64-v8a/libsigner.so","rb").read()
VA0,VA1=0xdb1cc,0xdb1cc+3188
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
lines=[]
for ins in md.disasm(elf[VA0:VA1],VA0):
    lines.append("%06x: %-8s %s"%(ins.address,ins.mnemonic,ins.op_str))
open("rev/_nsign_body.asm","w").write("\n".join(lines))
print("wrote",len(lines),"insns")
import re
print("=== blr / br ===")
for l in lines:
    if re.search(r"\b(blr|br|ret)\b",l): print("  ",l)
print("=== mov/movz/movk imm 0xc0/0xb0/0x100/0x140/192/176 ===")
for l in lines:
    if re.search(r"#0x(c0|b0)\b|#0x100\b|#0x140\b",l): print("  ",l)
