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
dynsym=S['.dynsym']; dynstr=S['.dynstr']
def symname(i):
    o=dynsym['off']+i*dynsym['entsize']; st=struct.unpack_from('<I',data,o)[0]
    s=dynstr['off']+st; return data[s:data.index(b'\0',s)].decode()
rela=S['.rela.plt']; got2sym={}
order=[]
for k in range(rela['size']//24):
    o=rela['off']+k*24
    r_off,r_info,_=struct.unpack_from('<QQq',data,o)
    got2sym[r_off]=symname(r_info>>32); order.append((r_off,symname(r_info>>32)))
plt=S['.plt']; md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
pins=list(md.disasm(data[plt['off']:plt['off']+plt['size']],plt['addr']))
# group into 16-byte entries
plt2sym={}
cur=None; base=None
for i in pins:
    if i.mnemonic=='adrp' and i.op_str.startswith('x16,'):
        base=i.operands[1].imm
    if i.mnemonic=='ldr' and i.op_str.startswith('x17, [x16'):
        off=0
        for op in i.operands[1:]:
            if op.type==capstone.arm64.ARM64_OP_IMM: off=op.imm
        g=base+off
        plt2sym[i.address & ~0xF] = got2sym.get(g,'?'+hex(g))
for k,v in sorted(plt2sym.items()):
    if v in ('read','fread','fopen','syscall','close','getrandom'):
        print(f"plt {hex(k)} = {v}")
t=S['.text']
insns=list(md.disasm(data[t['off']:t['off']+t['size']],t['addr']))
inv={}
for a,s in plt2sym.items(): inv.setdefault(s,[]).append(a)
for name in ('read','fread'):
    addrs=inv.get(name,[])
    callers=[]
    for i in insns:
        if i.mnemonic=='bl' and i.operands and i.operands[0].type==capstone.arm64.ARM64_OP_IMM:
            tgt=i.operands[0].imm
            if any(tgt==a for a in addrs): callers.append(hex(i.address))
    print(f"{name} plt={[hex(a) for a in addrs]} callers({len(callers)})={callers}")
