import struct, re
from capstone import *
LIB=r'C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so'
d=open(LIB,'rb').read()
# parse program headers
e_phoff=struct.unpack_from('<Q',d,0x20)[0]
e_phentsize=struct.unpack_from('<H',d,0x36)[0]
e_phnum=struct.unpack_from('<H',d,0x38)[0]
segs=[]
for i in range(e_phnum):
    o=e_phoff+i*e_phentsize
    p_type,p_flags=struct.unpack_from('<II',d,o)
    p_offset,p_vaddr,p_paddr,p_filesz,p_memsz=struct.unpack_from('<QQQQQ',d,o+8)
    if p_type==1: segs.append((p_vaddr,p_offset,p_filesz))
    print('PH',hex(p_type),'off',hex(p_offset),'va',hex(p_vaddr),'fsz',hex(p_filesz))
def va2off(va):
    for v,o,s in segs:
        if v<=va<v+s: return o+(va-v)
    return None
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
def dis(va,n):
    o=va2off(va)
    for i in md.disasm(d[o:o+n],va): yield i
# find all bl to 0x147d3c
target=0x147d3c
sites=[]
for i in dis(0,len(d)):
    if i.mnemonic=='bl':
        m=re.match(r'#(0x[0-9a-f]+)',i.op_str)
        if m and int(m.group(1),16)==target: sites.append(i.address)
print('bl 147d3c sites:',[hex(x) for x in sites])
