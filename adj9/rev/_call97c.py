from capstone import *
elf=open("../split_config.arm64_v8a/lib/arm64-v8a/libsigner.so","rb").read()
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
for name,va,n in (("call_site",0xdb850,0x70),("f_da97c",0xda97c,0x180)):
    print("="*14,name,hex(va))
    for ins in md.disasm(elf[va:va+n],va):
        print("  %06x: %-8s %s"%(ins.address,ins.mnemonic,ins.op_str))
