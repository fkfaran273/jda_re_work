import struct, capstone, sys
PATH=r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
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
t=S['.text']; md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
insns=list(md.disasm(data[t['off']:t['off']+t['size']],t['addr']))
REG=sys.argv[1]
lo=int(sys.argv[2],16); hi=int(sys.argv[3],16)
for i in insns:
    if not (lo<=i.address<=hi): continue
    if not i.operands: continue
    d=i.reg_name(i.operands[0].reg) if i.operands[0].type==capstone.arm64.ARM64_OP_REG else None
    if d==REG and i.mnemonic in ('mov','movz','movk','adr','adrp','ldr','ldrb','add','orr','sub','csel'):
        print(f"0x{i.address:x}  {i.mnemonic} {i.op_str}")
