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
    secs.append(dict(name=name,typ=typ,addr=addr,off=off,size=size,link=link,entsize=entsize))
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
plt=S['.plt']
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
base=None; plt2sym={}
for ins in md.disasm(elf[plt['off']:plt['off']+plt['size']],plt['addr']):
    if ins.mnemonic=='adrp' and ins.op_str.startswith('x16,'):
        base=ins.operands[1].imm
    if ins.mnemonic=='ldr' and ins.op_str.startswith('x17, [x16'):
        off=0
        for op in ins.operands[1:]:
            if op.type==ARM64_OP_IMM: off=op.imm
        g=base+off
        plt2sym[ins.address & ~0xF]=got2sym.get(g,'?%#x'%g)
for a in (0x148a00,0x148a10,0x148a20,0x1483e0):
    print(hex(a),"->",plt2sym.get(a,'(not a plt entry)'))
print("--- all plt ---")
for k in sorted(plt2sym): print("  %#x %s"%(k,plt2sym[k]))
