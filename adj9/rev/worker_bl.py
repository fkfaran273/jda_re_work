import struct, collections
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
for s in secs:
    secmap.append((sname(s[0]),s[3],s[4],s[6],s[5]))
def v2o(v):
    for sn,addr,off,link,size in secmap:
        if addr<=v<addr+size and addr!=0 and sn not in (".dynsym",".dynstr",".rela.plt",".rela.dyn",".gnu.hash",".dynstr",".symtab",".strtab"):
            return off+(v-addr)
    return v
dynsym=[s for s in secmap if s[0]==".dynsym"][0]
dynstr=[s for s in secmap if s[0]==".dynstr"][0]
syms={}
for i in range(dynsym[4]//24):
    off=dynsym[2]+i*24
    st_name,st_info,st_other,st_shndx,st_value,st_size=struct.unpack_from("<IBBHQQ",data,off)
    e=data.index(b"\0",dynstr[2]+st_name)
    syms[i]=data[dynstr[2]+st_name:e].decode()
relaplt=[s for s in secmap if s[0]==".rela.plt"][0]
plt_map={}
for i in range(relaplt[4]//24):
    off=relaplt[2]+i*24
    r_offset,r_info,r_addend=struct.unpack_from("<QQq",data,off)
    plt_map[r_offset]=syms.get(r_info>>32,"?")
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
plt=[s for s in secmap if s[0]==".plt"][0]
size=plt[4]; va=plt[1]
ent2sym={}
for e in range((size-32)//16):
    eva=va+32+e*16
    w0,w1,w2,w3=struct.unpack("<4I",data[plt[2]+32+e*16:plt[2]+32+e*16+16])
    immlo=(w0>>29)&3; immhi=(w0>>5)&0x7ffff
    imm=(immhi<<2)|immlo
    if imm>=(1<<20): imm-=(1<<21)
    page=((eva>>12)+imm)<<12
    imm12=(w1>>10)&0xfff
    got=page+imm12*8
    ent2sym[eva]=plt_map.get(got,"?")

def bls(start,size):
    no=v2o(start)
    code=data[no:no+size]
    out=[]
    for ins in md.disasm(code,start):
        if ins.mnemonic=="bl":
            out.append((ins.address,ins.operands[0].imm))
    return out
# walk the worker chain 0x95fc4, 0xbb548, 0xe2be0, and the two 0x13d/0x148 funcs
for fn,sz in ((0x95fc4,0x800),(0xbb548,0x800),(0xe2be0,0x1000),(0x13d874,0x800),(0x1483e0,0x1000),(0xda97c,0x800),(0xda6b8,0x800)):
    ts=bls(fn,sz)
    agg=collections.Counter()
    for a,t in ts:
        if t in ent2sym: nm="PLT:"+ent2sym[t]
        else: nm="local"
        agg[(t,nm)]+=1
    print("== 0x%x:"%fn, dict(agg))
