# randctx.py — dump code around both rand() call sites with PLT names
import struct,sys,os
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import capstone
from elf import ELF
e=ELF(r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so")
# build plt map
dynsym=e.byname[".dynsym"]; dynstr=e.byname[".dynstr"]
syms={}
for i in range(dynsym["size"]//24):
    off=dynsym["offset"]+i*24
    st_name,st_info,st_other,st_shndx,st_value,st_size=struct.unpack_from("<IBBHQQ",e.data,off)
    end=e.data.index(b"\0",dynstr["offset"]+st_name)
    syms[st_value]=e.data[dynstr["offset"]+st_name:end].decode() if st_value else None
# better: index by order for rela.plt
names=[]
for i in range(dynsym["size"]//24):
    off=dynsym["offset"]+i*24
    st_name=struct.unpack_from("<I",e.data,off)[0]
    end=e.data.index(b"\0",dynstr["offset"]+st_name)
    names.append(e.data[dynstr["offset"]+st_name:end].decode())
relaplt=e.byname[".rela.plt"]
got2sym={}
for i in range(relaplt["size"]//24):
    off=relaplt["offset"]+i*24
    r_offset,r_info,r_addend=struct.unpack_from("<QQq",e.data,off)
    got2sym[r_offset]=names[r_info>>32]
plt=e.byname[".plt"]
ent2sym={}
for i in range((plt["size"]-32)//16):
    eva=plt["addr"]+32+i*16
    wo=e.data[plt["offset"]+32+i*16:plt["offset"]+32+i*16+16]
    w0,w1=struct.unpack("<II",wo[0:8])
    immlo=(w0>>29)&3; immhi=(w0>>5)&0x7ffff
    imm=(immhi<<2)|immlo
    if imm>=(1<<20): imm-=(1<<21)
    page=((eva>>12)+imm)<<12
    imm12=(w1>>10)&0xfff
    ent2sym[eva]=got2sym.get(page+imm12*8,"?")
# find rand PLT
rand_plt=[k for k,v in ent2sym.items() if v in ("rand","srand","time","lrand48","random")]
print("rand-family PLT:",[(hex(k),v) for k,v in ent2sym.items() if v in("rand","srand","time","random","lrand48")])
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
t=e.byname[".text"]
def dump(center,before=0x80,after=0x140):
    lo=center-before
    off=e.vaddr_to_off(lo)
    n=e.vaddr_to_off(center+after)-off
    for ins in md.disasm(e.data[off:off+n],lo):
        extra=""
        if ins.mnemonic in ("bl","b") and ins.operands and ins.operands[0].type==capstone.arm64.ARM64_OP_IMM:
            tgt=ins.operands[0].imm
            if tgt in ent2sym: extra="  ;-> %s"%ent2sym[tgt]
            else: extra="  ;-> 0x%x"%tgt
        mark=" <<<<" if ins.address==center else ""
        print("0x%06x %-8s %-40s%s%s"%(ins.address,ins.mnemonic,ins.op_str,extra,mark))
for site in (0x12a2fc,0x12a31c,0x12cbbc):
    print("\n================ site 0x%x ================"%site)
    dump(site)
