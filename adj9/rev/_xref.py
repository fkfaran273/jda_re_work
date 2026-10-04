from capstone import *
import struct,sys
SO="../split_config.arm64_v8a/lib/arm64-v8a/libsigner.so"
elf=open(SO,"rb").read()
e_phoff=struct.unpack_from("<Q",elf,0x20)[0]
e_phentsize=struct.unpack_from("<H",elf,0x36)[0]
e_phnum=struct.unpack_from("<H",elf,0x38)[0]
segs=[]
for i in range(e_phnum):
    o=e_phoff+i*e_phentsize
    p_type,p_flags=struct.unpack_from("<II",elf,o)
    p_offset,p_vaddr,_,p_filesz,p_memsz=struct.unpack_from("<QQQQQ",elf,o+8)
    if p_type==1: segs.append((p_vaddr,p_offset,p_filesz,p_flags))
def va2off(va):
    for v,o,sz,fl in segs:
        if v<=va<v+sz: return o+(va-v)
    return None
def off2va(off):
    for v,o,sz,fl in segs:
        if o<=off<o+sz: return v+(off-o)
    return None
# executable segment (flags &1)
ex=[s for s in segs if s[3]&1][0]
v,o,sz,fl=ex
code=elf[o:o+sz]
base=v
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
targets={0x144214:"driver",0x1441e4:"fold_wrap",0x144074:"fold_xor",0x143b20:"slot_search",0xdb1cc:"nSign"}
callers={k:[] for k in targets}
for ins in md.disasm(code,base):
    if ins.mnemonic=="bl":
        try: t=int(ins.op_str,16)
        except: continue
        if t in targets: callers[t].append(ins.address)
    if ins.mnemonic in ("b","bl"):
        pass
for k,name in targets.items():
    print(name,hex(k),"callers:",[hex(c) for c in callers[k]])
# also: who references via adrp/add the fold region? print nSign bl targets summary
print("--- nSign bl targets (0xdab84..0xdc7ec) ---")
from collections import Counter
cnt=Counter()
for ins in md.disasm(code,base):
    if 0xdab84<=ins.address<0xdc7ec and ins.mnemonic=="bl":
        try: t=int(ins.op_str,16)
        except: continue
        cnt[t]+=1
for t,c in sorted(cnt.items(),key=lambda x:-x[1]):
    print("  %x x%d"%(t,c))
