import struct
from capstone import *
so="C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data=open(so,"rb").read()
# section table for vaddr->file offset
e_shoff=struct.unpack_from("<Q",data,0x28)[0]
e_shentsize=struct.unpack_from("<H",data,0x3a)[0]
e_shnum=struct.unpack_from("<H",data,0x3c)[0]
e_shstrndx=struct.unpack_from("<H",data,0x3e)[0]
secs=[]
for i in range(e_shnum):
    off=e_shoff+i*e_shentsize
    name,typ,flags,addr,offset,size,link,info,align,entsize=struct.unpack_from("<IIQQQQIIQQ",data,off)
    secs.append((name,typ,flags,addr,offset,size,link,info,align,entsize))
shstr=secs[e_shstrndx]
def sname(n):
    e=data.index(b"\0",shstr[4]+n)
    return data[shstr[4]+n:e].decode()
secmap=[]
for s in secs:
    sn=sname(s[0])
    secmap.append((sn,s[3],s[4],s[6],s[5]))  # name,addr,offset,link,size
def v2o(v):
    for sn,addr,off,link,size in secmap:
        if sn in (".plt",".text",".rodata",".data",".bss",".got",".data.rel.ro") and addr<=v<addr+size and addr!=0:
            return off+(v-addr)
    # fallback: PT_LOAD map: for this .so offsets==vaddr below 0x150000 mostly
    return v
def o2v(o):
    for sn,addr,off,link,size in secmap:
        if off<=o<off+size and addr!=0:
            return addr+(o-off)
    return o
# dynsym names
dynsym=[s for s in secmap if s[0]==".dynsym"][0]
dynstr=[s for s in secmap if s[0]==".dynstr"][0]
syms={}
n=dynsym[4]//24
for i in range(n):
    off=dynsym[2]+i*24
    st_name,st_info,st_other,st_shndx,st_value,st_size=struct.unpack_from("<IBBHQQ",data,off)
    e=data.index(b"\0",dynstr[2]+st_name)
    nm=data[dynstr[2]+st_name:e].decode()
    syms[i]=nm
# .rela.plt to map plt slot -> symbol
relaplt=[s for s in secmap if s[0]==".rela.plt"][0]
plt_map={}
nrel=relaplt[4]//24
for i in range(nrel):
    off=relaplt[2]+i*24
    r_offset,r_info,r_addend=struct.unpack_from("<QQq",data,off)
    symidx=r_info>>32
    plt_map[r_offset]=syms.get(symidx,"?")
# parse .plt: each entry 16 bytes; got loads at entry+12 map to got offsets
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
md.detail=True
plt=[s for s in secmap if s[0]==".plt"][0]
plt_got={}
o=plt[2]
size=plt[4]
# PLT0 is 32 bytes, entries 16 bytes after
code=data[o+32:o+size]
va=plt[1]+32
import collections
# simpler: disassemble each 16-byte entry
NENT=(size-32)//16
for e in range(NENT):
    eva=va+e*16
    b=data[o+32+e*16:o+32+e*16+16]
    # adrp value: compute page from eva + imm*4096
    w0,w1,w2,w3=struct.unpack("<4I",b)
    # adrp x16: bits: immlo(2)|10000|immhi(19)|Rd
    w=w0
    rd=w&0x1f
    immlo=(w>>29)&3
    immhi=(w>>5)&0x7ffff
    imm=(immhi<<2)|immlo
    if imm>=(1<<20): imm-=(1<<21)
    page=((eva>>12)+imm)<<12
    # ldr x17,[x16,#imm12]  w1: 1111100101 imm12 Rn Rt
    imm12=(w1>>10)&0xfff
    gotaddr=page+imm12*8
    plt_got[eva]=gotaddr
# map: entry va -> symbol
ent2sym={eva:plt_map.get(g,"?") for eva,g in plt_got.items()}
# Now scan nSign range for bl
NS=0xdb1cc; SZ=3188
no=v2o(NS)
code=data[no:no+SZ]
targets=collections.Counter()
bl_list=[]
for ins in md.disasm(code,NS):
    if ins.mnemonic=="bl":
        t=ins.operands[0].imm
        bl_list.append((ins.address,t))
        targets[t]+=1
print("bl count:",len(bl_list),"unique:",len(targets))
for t,c in sorted(targets.items()):
    if t in ent2sym:
        print("  0x%x -> PLT %s x%d"%(t,ent2sym[t],c))
    else:
        print("  0x%x -> local x%d"%(t,c))
