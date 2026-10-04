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
lo=int(sys.argv[1],16); hi=int(sys.argv[2],16)
for i in insns:
    if lo<=i.address<=hi and i.mnemonic in ('ret','sub') and (i.mnemonic=='ret' or i.op_str.startswith('sp, sp')):
        print(f"0x{i.address:x}  {i.mnemonic} {i.op_str}")
