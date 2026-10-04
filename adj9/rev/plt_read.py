import struct, capstone
PATH = r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data=open(PATH,'rb').read()
e_shoff=struct.unpack_from('<Q',data,0x28)[0]; e_shentsize=struct.unpack_from('<H',data,0x3a)[0]
e_shnum=struct.unpack_from('<H',data,0x3c)[0]; e_shstrndx=struct.unpack_from('<H',data,0x3e)[0]
secs=[]
for i in range(e_shnum):
    o=e_shoff+i*e_shentsize
    name,typ,flags,addr,off,size,link,info,align,entsize=struct.unpack_from('<IIQQQQIIQQ',data,o)
    secs.append(dict(name=name,typ=typ,addr=addr,off=off,size=size,link=link,entsize=entsize))
sh=secs[e_shstrndx]
def nm(n):
    s=sh['off']+n; return data[s:data.index(b'\0',s)].decode()
S={}
for s in secs: s['nm']=nm(s['name']); S[s['nm']]=s
dynsym=S['.dynsym']; dynstr=S['.dynstr']; rela=S.get('.rela.plt')
def symname(i):
    o=dynsym['off']+i*dynsym['entsize']
    st_name=struct.unpack_from('<I',data,o)[0]
    s=dynstr['off']+st_name
    return data[s:data.index(b'\0',s)].decode()
# rela.plt
entries=[]
for k in range(rela['size']//24):
    o=rela['off']+k*24
    r_offset,r_info,r_addend=struct.unpack_from('<QQq',data,o)
    sym=r_info>>32
    entries.append((r_offset,symname(sym)))
# .plt section
plt=S.get('.plt')
base=plt['addr']
print("PLT base",hex(base))
slot={}
for k,(r_off,sym) in enumerate(entries):
    addr=base+k*16
    slot[sym]=addr
    if sym in ('read','openat','close','fopen','fread','syscall'):
        print(f"  {sym:10s} -> plt {hex(addr)}  (got {hex(r_off)})")
# find callers of read PLT
t=S['.text']; md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
insns=list(md.disasm(data[t['off']:t['off']+t['size']],t['addr']))
for name in ('read','fread'):
    a=slot.get(name)
    if not a: continue
    callers=[hex(i.address) for i in insns if i.mnemonic=='bl' and i.operands and i.operands[0].type==capstone.arm64.ARM64_OP_IMM and i.operands[0].imm==a]
    print(f"{name} callers ({len(callers)}):", callers)
