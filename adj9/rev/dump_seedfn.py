import struct
from capstone import *
so="C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data=open(so,"rb").read()
# reuse section parsing (quick)
import importlib.util
spec=importlib.util.spec_from_file_location("fb","rev/find_srand.py")
# just re-parse inline
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
        if addr<=v<addr+size and addr!=0 and not sn.startswith((".dyn",".rela",".gnu",".symtab",".strtab",".debug")):
            return off+(v-addr)
    return v
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
# srand caller function: find start. srand bl at 0x12cbc0. Dump window 0x12cb40..0x12cc80
for lo,hi,label in ((0x12a2c0,0x12a360,"rand users"),(0x12a360,0x12a420,"rand users2")):
    print("==== %s ===="%label)
    no=v2o(lo)
    code=data[no:v2o(hi)]
    for ins in md.disasm(code,lo):
        extra=""
        if ins.mnemonic in ("bl",):
            extra="; -> 0x%x"%ins.operands[0].imm
        print("0x%x  %-8s %s%s"%(ins.address,ins.mnemonic,ins.op_str,extra))
