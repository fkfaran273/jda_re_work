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
# eh_frame could give fde starts; skip: use prologue scan.
# scan back from target for 'sub sp' style function starts is unreliable; instead
# linear-scan the .text from a bit before, tracking typical prologue: stp x29,x30,[sp,#-..]!
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
target=int(sys.argv[1],16)
lo=target-0x3000
no=v2o(lo)
code=data[no:v2o(target)+0x40]
starts=[]
for ins in md.disasm(code,lo):
    if ins.mnemonic=="stp" and "x29, x30" in ins.op_str and "sp" in ins.op_str:
        starts.append(ins.address)
# also function ends: 'ret' followed by next start
fs=[s for s in starts if s<=target]
fnstart=max(fs) if fs else None
print("function start guess: 0x%x"%fnstart)
# dump from fnstart to next start after target (cap 0x2000)
nxt=[s for s in starts if s>fnstart]
end=min(nxt) if nxt else fnstart+0x2000
print("end: 0x%x size 0x%x"%(end,end-fnstart))
no=v2o(fnstart)
for ins in md.disasm(data[no:v2o(end)],fnstart):
    extra=""
    if ins.mnemonic=="bl": extra="   ; -> 0x%x"%ins.operands[0].imm
    print("0x%x  %-8s %s%s"%(ins.address,ins.mnemonic,ins.op_str,extra))
