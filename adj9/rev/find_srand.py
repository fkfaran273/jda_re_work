import struct
from capstone import *
so="C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data=open(so,"rb").read()
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
for s in secs: secmap.append((sname(s[0]),s[3],s[4],s[6],s[5]))
# .text bounds
text=[s for s in secmap if s[0]==".text"][0]
# find srand/rand/time/gettimeofday/clock_gettime plt entries
dynsym=[s for s in secmap if s[0]==".dynsym"][0]
dynstr=[s for s in secmap if s[0]==".dynstr"][0]
syms={}
for i in range(dynsym[4]//24):
    off=dynsym[2]+i*24
    st_name,st_info,st_other,st_shndx,st_value,st_size=struct.unpack_from("<IBBHQQ",data,off)
    e=data.index(b"\0",dynstr[2]+st_name)
    syms[i]=data[dynstr[2]+st_name:e].decode()
relaplt=[s for s in secmap if s[0]==".rela.plt"][0]
got2sym={}
for i in range(relaplt[4]//24):
    off=relaplt[2]+i*24
    r_offset,r_info,r_addend=struct.unpack_from("<QQq",data,off)
    got2sym[r_offset]=syms.get(r_info>>32,"?")
plt=[s for s in secmap if s[0]==".plt"][0]
ent2sym={}
for e in range((plt[4]-32)//16):
    eva=plt[1]+32+e*16
    w0,w1,w2,w3=struct.unpack("<4I",data[plt[2]+32+e*16:plt[2]+32+e*16+16])
    immlo=(w0>>29)&3; immhi=(w0>>5)&0x7ffff
    imm=(immhi<<2)|immlo
    if imm>=(1<<20): imm-=(1<<21)
    page=((eva>>12)+imm)<<12
    imm12=(w1>>10)&0xfff
    ent2sym[eva]=got2sym.get(page+imm12*8,"?")
print("srand plt:",[hex(k) for k,v in ent2sym.items() if v=="srand"])
print("rand plt:",[hex(k) for k,v in ent2sym.items() if v=="rand"])
print("time plt:",[hex(k) for k,v in ent2sym.items() if v=="time"])
print("gettimeofday:",[hex(k) for k,v in ent2sym.items() if v=="gettimeofday"])
# disassemble whole .text; find bl to srand/rand/time plt
taddr,toff,tsize=text[1],text[2],text[4]
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
code=data[toff:toff+tsize]
callers={n:[] for n in ("srand","rand","time","gettimeofday","clock_gettime","fmod","localtime")}
for ins in md.disasm(code,taddr):
    if ins.mnemonic=="bl":
        t=ins.operands[0].imm
        nm=ent2sym.get(t)
        if nm in callers: callers[nm].append(hex(ins.address))
for k,v in callers.items(): print(k,"callers:",v)
