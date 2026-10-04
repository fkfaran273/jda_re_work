# same as dump_fn2 but annotates PLT bl targets with symbol names
import struct, sys
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
def v2o(v):
    for sn,addr,off,link,size in secmap:
        if addr<=v<addr+size and addr!=0 and not sn.startswith((".dyn",".rela",".gnu",".symtab",".strtab",".debug",".eh")):
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
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
ehh=[s for s in secmap if s[0]==".eh_frame_hdr"][0]
base=ehh[1]; off=ehh[2]
ehfp_enc,fc_enc,tbl_enc=struct.unpack_from("<BBB",data,off+1)
p=off+4
def read_enc(enc,p,base):
    if enc==0x1b:
        v=struct.unpack_from("<i",data,p)[0]
        return base+(p-off)+v, p+4
    if enc==0x03: return struct.unpack_from("<I",data,p)[0], p+4
    if enc==0x0b: return struct.unpack_from("<Q",data,p)[0], p+8
    raise Exception("enc %x"%enc)
fdep,p=read_enc(ehfp_enc,p,base)
fc,p=read_enc(fc_enc,p,base)
locs=[]
table=p
for i in range(fc):
    loc=struct.unpack_from("<i",data,table+i*8)[0]
    locs.append(loc)
locs=sorted(locs)
target=int(sys.argv[1],16)
lo=None
for l in locs:
    if l<=target: lo=l
    else: break
hi=next((l for l in locs if l>target), target+0x2000)
print("FDE function: 0x%x .. 0x%x size 0x%x"%(lo,hi,hi-lo))
no=v2o(lo)
for ins in md.disasm(data[no:v2o(hi)],lo):
    extra=""
    if ins.mnemonic=="bl":
        t=ins.operands[0].imm
        nm=ent2sym.get(t)
        extra="   ; -> %s%s"%(nm,hex(t) if nm=="?" else "")
    print("0x%x  %-8s %s%s"%(ins.address,ins.mnemonic,ins.op_str,extra))
