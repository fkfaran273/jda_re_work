import struct
elf=open("../split_config.arm64_v8a/lib/arm64-v8a/libsigner.so","rb").read()
e_phoff=struct.unpack_from("<Q",elf,0x20)[0]
e_phentsize=struct.unpack_from("<H",elf,0x36)[0]
e_phnum=struct.unpack_from("<H",elf,0x38)[0]
for i in range(e_phnum):
    o=e_phoff+i*e_phentsize
    p_type,p_flags=struct.unpack_from("<II",elf,o)
    p_offset,p_vaddr,_,p_filesz,p_memsz=struct.unpack_from("<QQQQQ",elf,o+8)
    if p_type==1:
        print("LOAD off=%#x va=%#x filesz=%#x memsz=%#x flags=%d(%s%s%s)"%(
            p_offset,p_vaddr,p_filesz,p_memsz,p_flags,
            "R" if p_flags&4 else "-","W" if p_flags&2 else "-","X" if p_flags&1 else "-"))
