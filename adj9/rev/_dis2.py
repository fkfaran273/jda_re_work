from capstone import *
import struct
SO="../split_config.arm64_v8a/lib/arm64-v8a/libsigner.so"
elf=open(SO,"rb").read()
# parse ELF program headers for va->off
e_phoff=struct.unpack_from("<Q",elf,0x20)[0]
e_phentsize=struct.unpack_from("<H",elf,0x36)[0]
e_phnum=struct.unpack_from("<H",elf,0x38)[0]
segs=[]
for i in range(e_phnum):
    o=e_phoff+i*e_phentsize
    p_type,p_flags=struct.unpack_from("<II",elf,o)
    p_offset,p_vaddr,p_paddr,p_filesz,p_memsz=struct.unpack_from("<QQQQQ",elf,o+8)
    if p_type==1: segs.append((p_vaddr,p_offset,p_filesz,p_flags))
def va2off(va):
    for v,o,sz,fl in segs:
        if v<=va<v+sz: return o+(va-v)
    return None
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
def dis(name,va,n):
    print("="*16,name,hex(va))
    off=va2off(va)
    for ins in md.disasm(elf[off:off+n],va):
        print("  %08x: %-8s %s"%(ins.address,ins.mnemonic,ins.op_str))
dis("sub_143b20",0x143b20,0x160)
dis("driver_144214",0x144214,0x260)
