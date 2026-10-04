from capstone import *
elf=open("../split_config.arm64_v8a/lib/arm64-v8a/libsigner.so","rb").read()
# need va->file mapping. use prior known: first PT_LOAD p_offset=0,p_vaddr=0
def va2off(va): return va  # identity for first segment
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
for name,va,n in (("driver_144214",0x144214,0x100),
                  ("sub_1441e4",0x1441e4,0x40),
                  ("sub_144074",0x144074,0x180)):
    print("="*20,name,hex(va))
    off=va2off(va)
    for ins in md.disasm(elf[off:off+n],va):
        print("  %08x: %-8s %s"%(ins.address,ins.mnemonic,ins.op_str))
