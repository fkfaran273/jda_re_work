import struct
elf=open("../split_config.arm64_v8a/lib/arm64-v8a/libsigner.so","rb").read()
e_shoff=struct.unpack_from("<Q",elf,0x28)[0]; e_shentsize=struct.unpack_from("<H",elf,0x3a)[0]
e_shnum=struct.unpack_from("<H",elf,0x3c)[0]; e_shstrndx=struct.unpack_from("<H",elf,0x3e)[0]
secs=[]
for i in range(e_shnum):
    o=e_shoff+i*e_shentsize
    name,typ,flags,addr,off,size,link,info,align,entsize=struct.unpack_from("<IIQQQQIIQQ",elf,o)
    secs.append(dict(name=name,typ=typ,flags=flags,addr=addr,off=off,size=size,link=link,entsize=entsize))
sh=secs[e_shstrndx]
def nm(n):
    s=sh['off']+n; return elf[s:elf.index(b"\0",s)].decode()
S={}
for s in secs: s['nm']=nm(s['name']); S[s['nm']]=s
dynsym=S['.dynsym']; dynstr=S['.dynstr']
n=dynsym['size']//dynsym['entsize']
print("dynsym entries:",n)
for i in range(n):
    o=dynsym['off']+i*dynsym['entsize']
    st,info,other,shndx,val,sz=struct.unpack_from("<IBBHQQ",elf,o)
    if st==0: continue
    s=dynstr['off']+st; name=elf[s:elf.index(b"\0",s)].decode()
    bind=info>>4; typ=info&0xf
    if shndx!=0 or typ==2:  # defined or function
        print("  %-40s val=%#x size=%d bind=%d typ=%d shndx=%d"%(name,val,sz,bind,typ,shndx))
