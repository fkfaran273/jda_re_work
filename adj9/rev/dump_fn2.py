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
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
# eh_frame FDE parse: .eh_frame_hdr has a binary search table of (sdata4 loc, sdata4 fde)
ehh=[s for s in secmap if s[0]==".eh_frame_hdr"][0]
base=ehh[1]; off=ehh[2]
ver,eflags,tflen,tableenc=struct.unpack_from("<BBBB",data,off)
off2=off+8
# walk: length byte then unit... simpler: header has ptr to table: after 4 dwords comes sdata4 pairs? Format:
# eh_frame_hdr: version(1) eh_frame_ptr_enc(1) fde_count_enc(1) table_enc(1) eh_frame_ptr fde_count table...
ehfp_enc,fc_enc,tbl_enc=struct.unpack_from("<BBB",data,off+1)
p=off+4
# eh_frame_ptr_enc likely 0x1b (sdata4 pcrel)
def read_enc(enc,p,base):
    if enc==0x1b:
        v=struct.unpack_from("<i",data,p)[0]
        return base+(p-off)+v, p+4
    if enc==0x03:
        return struct.unpack_from("<I",data,p)[0], p+4
    if enc==0x0b:
        return struct.unpack_from("<Q",data,p)[0], p+8
    raise Exception("enc %x"%enc)
fdep,p=read_enc(ehfp_enc,p,base)
fc,p=read_enc(fc_enc,p,base)
fde_starts=[]
table=p
for i in range(fc):
    loc=struct.unpack_from("<i",data,table+i*8)[0]
    fde=struct.unpack_from("<i",data,table+i*8+4)[0]
    fde_starts.append((base+(table-off)+i*8+loc if False else loc, fde))
locs=sorted(l for l,f in fde_starts)
print("fde count:",fc)
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
    if ins.mnemonic=="bl": extra="   ; -> 0x%x"%ins.operands[0].imm
    if ins.mnemonic=="adrp": extra="   ; page"
    print("0x%x  %-8s %s%s"%(ins.address,ins.mnemonic,ins.op_str,extra))
