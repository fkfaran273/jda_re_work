import struct, capstone
PATH = r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data=open(PATH,'rb').read()
e_shoff=struct.unpack_from('<Q',data,0x28)[0]; e_shentsize=struct.unpack_from('<H',data,0x3a)[0]
e_shnum=struct.unpack_from('<H',data,0x3c)[0]; e_shstrndx=struct.unpack_from('<H',data,0x3e)[0]
secs=[]
for i in range(e_shnum):
    o=e_shoff+i*e_shentsize
    name,typ,flags,addr,off,size,link,info,align,entsize=struct.unpack_from('<IIQQQQIIQQ',data,o)
    secs.append(dict(name=name,addr=addr,off=off,size=size))
sh=secs[e_shstrndx]
def nm(n):
    s=sh['off']+n; return data[s:data.index(b'\0',s)].decode()
S={}
for s in secs: s['nm']=nm(s['name']); S[s['nm']]=s
t=S['.text']; base,off,size=t['addr'],t['off'],t['size']
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
insns=list(md.disasm(data[off:off+size],base))
idx={i.address:k for k,i in enumerate(insns)}
SYSCALL=0x148b30
# arm64 syscall table (partial)
NAMES={56:'openat',63:'read',64:'write',57:'close',278:'getrandom',29:'ioctl',80:'fstat',62:'lseek',
       169:'gettimeofday',113:'clock_gettime',48:'faccessat',101:'nanosleep',222:'mmap',215:'munmap'}
for k,i in enumerate(insns):
    if i.mnemonic=='bl' and i.operands and i.operands[0].type==capstone.arm64.ARM64_OP_IMM and i.operands[0].imm==SYSCALL:
        # look back for w0/w8 set
        num=None; path=None
        for j in range(k-1,max(0,k-14),-1):
            ij=insns[j]
            if ij.mnemonic in ('mov','movz') and ij.op_str.startswith('w0, #') and num is None:
                num=ij.operands[1].imm
            if ij.mnemonic=='adr' and ij.op_str.startswith('x2,'):
                path=ij.operands[1].imm
        print(f"0x{i.address:x}  syscall nr={num} ({NAMES.get(num,'?')}) path/arg2={hex(path) if path else '-'}")
