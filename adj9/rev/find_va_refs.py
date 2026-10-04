import sys, struct, capstone
PATH = r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data = open(PATH,'rb').read()
e_shoff=struct.unpack_from('<Q',data,0x28)[0]
e_shentsize=struct.unpack_from('<H',data,0x3a)[0]
e_shnum=struct.unpack_from('<H',data,0x3c)[0]
e_shstrndx=struct.unpack_from('<H',data,0x3e)[0]
secs=[]
for i in range(e_shnum):
    o=e_shoff+i*e_shentsize
    name,typ,flags,addr,off,size,link,info,align,entsize=struct.unpack_from('<IIQQQQIIQQ',data,o)
    secs.append(dict(name=name,addr=addr,off=off,size=size))
sh=secs[e_shstrndx]
def nm(n):
    s=sh['off']+n; return data[s:data.index(b'\0',s)].decode()
S={}
for s in secs:
    s['nm']=nm(s['name']); S[s['nm']]=s
t=S['.text']; base,off,size=t['addr'],t['off'],t['size']
code=data[off:off+size]
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
insns=list(md.disasm(code,base))
targets=[int(x,16) for x in sys.argv[1:]]
def reg(i,o): return i.reg_name(i.operands[o].reg) if i.operands[o].type==capstone.arm64.ARM64_OP_REG else None
def imm(i,o): return i.operands[o].imm if i.operands[o].type==capstone.arm64.ARM64_OP_IMM else None
for T in targets:
    hits=[]
    for k,i in enumerate(insns):
        if i.mnemonic=='adr':
            if imm(i,1)==T: hits.append((hex(i.address),'adr',hex(T)))
        elif i.mnemonic=='adrp':
            page=imm(i,1)
            if page is None: continue
            r=reg(i,0)
            for j in range(k+1,min(k+12,len(insns))):
                ij=insns[j]
                if ij.mnemonic in ('adrp','b','bl','ret','b.eq','b.ne'): break
                if ij.mnemonic in ('add','sub') and len(ij.operands)>=3 and reg(ij,0)==r and reg(ij,1)==r:
                    v=imm(ij,2)
                    if v is None: continue
                    val=page+v if ij.mnemonic=='add' else page-v
                    if val==T: hits.append((hex(i.address),'adrp+'+ij.mnemonic,hex(val)))
                if ij.mnemonic in ('ldr','ldrb','ldrh','ldrsw','str','strb') and reg(ij,1)==r:
                    v=0
                    for op in ij.operands[2:]:
                        if op.type==capstone.arm64.ARM64_OP_IMM: v=op.imm
                    if page+v==T: hits.append((hex(i.address),'adrp+'+ij.mnemonic,hex(T)))
    print(f"--- refs to {hex(T)}: {len(hits)}")
    for h in hits[:60]: print("   ",h)
