import struct
elf=open("../split_config.arm64_v8a/lib/arm64-v8a/libsigner.so","rb").read()
e_shoff=struct.unpack_from("<Q",elf,0x28)[0]
e_shentsize=struct.unpack_from("<H",elf,0x3a)[0]
e_shnum=struct.unpack_from("<H",elf,0x3c)[0]
e_shstrndx=struct.unpack_from("<H",elf,0x3e)[0]
def sh(i):
    o=e_shoff+i*e_shentsize
    name,typ,flags,addr,off,size=struct.unpack_from("<IIQQQQ",elf,o)
    return name,typ,flags,addr,off,size
stroff=sh(e_shstrndx)[4]
for i in range(e_shnum):
    name,typ,flags,addr,off,size=sh(i)
    nm=elf[stroff+name:elf.index(b"\0",stroff+name)].decode()
    if nm in (".text",".plt",".rodata",".data",".data.rel.ro"):
        print("%-14s addr=%#x off=%#x size=%#x"%(nm,addr,off,size))
