# nsign_strrefs.py — dump all adrp+add string references inside the nSign window
import struct
from capstone import *
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

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
secmap=[(sname(s[0]),s[3],s[4],s[6],s[5]) for s in secs]
text=[s for s in secmap if s[0]==".text"][0]
taddr,toff,tsize=text[1],text[2],text[4]

def v2o(v):
    for sn_,addr,off,link,size in secmap:
        if addr<=v<addr+size and addr!=0:
            return off+(v-addr), sn_
    return None,None

md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
code=data[toff:toff+tsize]
adrp={}
out=[]
for ins in md.disasm(code,taddr):
    if ins.mnemonic=="adrp":
        adrp[ins.operands[0].reg]=ins.operands[1].imm
    elif ins.mnemonic=="add" and len(ins.operands)==3 and \
         ins.operands[0].type==ARM64_OP_REG and ins.operands[2].type==ARM64_OP_IMM:
        rd=ins.operands[0].reg; rn=ins.operands[1].reg; imm=ins.operands[2].imm
        if rn in adrp:
            va=adrp[rn]+imm
            po,snm=v2o(va)
            if po and snm in (".data",".rodata",".bss"):
                b=data[po:po+40]
                out.append((ins.address,va,snm,b))
    # clear reg when re-defined as dest of non-add (keep simple: keep last)

# nSign window
LO,HI=0xdab84,0xdc7ec
for a,va,snm,b in out:
    if LO<=a<=HI:
        pr=''.join(chr(c) if 32<=c<127 else '.' for c in b)
        print("0x%x -> 0x%x %s: %s"%(a,va,snm,pr))
# also: same refs from the rand function window
print("=== rand fn 0x1294c4..0x12a7b0 ===")
for a,va,snm,b in out:
    if 0x1294c4<=a<=0x12a7b0:
        pr=''.join(chr(c) if 32<=c<127 else '.' for c in b)
        print("0x%x -> 0x%x %s: %s"%(a,va,snm,pr))
# and srand fn window
print("=== srand fn 0x12cad4..0x12cce8 ===")
for a,va,snm,b in out:
    if 0x12cad4<=a<=0x12cce8:
        pr=''.join(chr(c) if 32<=c<127 else '.' for c in b)
        print("0x%x -> 0x%x %s: %s"%(a,va,snm,pr))
