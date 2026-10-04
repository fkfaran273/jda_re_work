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
    secs.append(dict(name=name,addr=addr,off=off,size=size,entsize=entsize))
sh=secs[e_shstrndx]
def nm(n):
    s=sh['off']+n; return elf[s:elf.index(b"\0",s)].decode()
S={}
for s in secs: s['nm']=nm(s['name']); S[s['nm']]=s
dynsym=S['.dynsym']; dynstr=S['.dynstr']
def symname(i):
    o=dynsym['off']+i*dynsym['entsize']; st=struct.unpack_from("<I",elf,o)[0]
    s=dynstr['off']+st; return elf[s:elf.index(b"\0",s)].decode()
rela=S['.rela.plt']; got2sym={}
for k in range(rela['size']//24):
    o=rela['off']+k*24
    r_off,r_info,_=struct.unpack_from("<QQq",elf,o); got2sym[r_off]=symname(r_info>>32)
plt=S['.plt']; md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
base=None; plt2sym={}
for ins in md.disasm(elf[plt['off']:plt['off']+plt['size']],plt['addr']):
    if ins.mnemonic=='adrp' and ins.op_str.startswith('x16,'): base=ins.operands[1].imm
    if ins.mnemonic=='ldr' and ins.op_str.startswith('x17, [x16'):
        off=0
        for op in ins.operands:
            if op.type==ARM64_OP_MEM: off=op.mem.disp
        plt2sym[ins.address & ~0xF]=got2sym.get(base+off,'?%#x'%(base+off))
TVA,TOFF,TSZ=0x8be0,0x8be0,0x13fdd4
code=elf[TOFF:TOFF+TSZ]
bls=[]
for ins in md.disasm(code,TVA):
    if ins.mnemonic=="bl":
        bls.append((ins.address,int(ins.op_str.lstrip("#"),16)))
bls.sort()
starts=sorted(set(t for _,t in bls)|{0xdb1cc})
import bisect
def owner(addr):
    i=bisect.bisect_right(starts,addr)-1
    return starts[i] if i>=0 else None
from collections import defaultdict
callees=defaultdict(set); pltcalls=defaultdict(set)
for a,t in bls:
    o=owner(a)
    if o is None: continue
    if t in plt2sym: pltcalls[o].add(plt2sym[t])
    else: callees[o].add(t)
# BFS from nSign
seen=set([0xdb1cc]); stack=[0xdb1cc]
while stack:
    f=stack.pop()
    for c in callees.get(f,()):
        if c not in seen: seen.add(c); stack.append(c)
print("nSign transitive closure size:",len(seen))
imports=defaultdict(set)
for f in seen:
    for p in pltcalls.get(f,()): imports[p].add(f)
print("\nPLT imports reachable from nSign:")
for p in sorted(imports): print("  %-24s from %d fns"%(p,len(imports[p])))
print("\nfunctions in closure that call entropy-ish imports:")
for p in ("gettimeofday","clock_gettime","time","srand","rand","fopen","fread","read","syscall","getpid","getauxval","__system_property_get"):
    if p in imports: print("  %-20s %s"%(p,[hex(x) for x in sorted(imports[p])][:12]))
