import struct
from capstone import *
from capstone.arm64 import *
elf=open("../split_config.arm64_v8a/lib/arm64-v8a/libsigner.so","rb").read()
e_shoff=struct.unpack_from("<Q",elf,0x28)[0]; e_shentsize=struct.unpack_from("<H",elf,0x3a)[0]
e_shnum=struct.unpack_from("<H",elf,0x3c)[0]; e_shstrndx=struct.unpack_from("<H",elf,0x3e)[0]
secs=[]
for i in range(e_shnum):
    o=e_shoff+i*e_shentsize
    name,typ,flags,addr,off,size,link,info,align,entsize=struct.unpack_from("<IIQQQQIIQQ",elf,o)
    secs.append(dict(name=name,typ=typ,flags=flags,addr=addr,off=off,size=size,link=link,entsize=entsize))
sh=secs[e_shstrndx]
def nm(n):
    s=sh['off']+n; return elf[s:elf.index(b"\0",s)].decode()
S={}
for s in secs: s['nm']=nm(s['name']); S[s['nm']]=s
dynsym=S['.dynsym']; dynstr=S['.dynstr']
def symname(i):
    o=dynsym['off']+i*dynsym['entsize']; st=struct.unpack_from("<I",elf,o)[0]
    s=dynstr['off']+st; return elf[s:elf.index(b"\0",s)].decode()
rela=S['.rela.plt']
got2sym={}
for k in range(rela['size']//24):
    o=rela['off']+k*24
    r_off,r_info,_=struct.unpack_from("<QQq",elf,o)
    got2sym[r_off]=symname(r_info>>32)
plt=S['.plt']; md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
base=None; plt2sym={}
for ins in md.disasm(elf[plt['off']:plt['off']+plt['size']],plt['addr']):
    if ins.mnemonic=='adrp' and ins.op_str.startswith('x16,'): base=ins.operands[1].imm
    if ins.mnemonic=='ldr' and ins.op_str.startswith('x17, [x16'):
        off=0
        for op in ins.operands:
            if op.type==ARM64_OP_MEM: off=op.mem.disp
        plt2sym[ins.address & ~0xF]=got2sym.get(base+off,'?')
VA0,VA1=0xdb1cc,0xdb1cc+3188
for ins in md.disasm(elf[VA0:VA1],VA0):
    m=ins.mnemonic; o=ins.op_str
    if m=="bl":
        t=int(o.lstrip("#"),16)
        tag=plt2sym.get(t,"")
        print("  %06x: bl %#x %s"%(ins.address,t,tag))
