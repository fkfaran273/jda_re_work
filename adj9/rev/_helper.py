from capstone import *
elf=open("../split_config.arm64_v8a/lib/arm64-v8a/libsigner.so","rb").read()
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
for name,va,n in (("h_1483e0",0x1483e0,0x60),("h_1483d0",0x1483d0,0x80),
                  ("nSign_tail",0xdbdf0,0x50),("nSign_head",0xdb1cc,0x60)):
    print("="*14,name,hex(va))
    for ins in md.disasm(elf[va:va+n],va):
        print("  %06x: %-8s %s"%(ins.address,ins.mnemonic,ins.op_str))
