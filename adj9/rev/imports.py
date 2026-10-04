import struct
so="C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data=open(so,"rb").read()
# parse ELF64 sections
e_shoff=struct.unpack_from("<Q",data,0x28)[0]
e_shentsize=struct.unpack_from("<H",data,0x3a)[0]
e_shnum=struct.unpack_from("<H",data,0x3c)[0]
e_shstrndx=struct.unpack_from("<H",data,0x3e)[0]
secs=[]
for i in range(e_shnum):
    off=e_shoff+i*e_shentsize
    name,typ,flags,addr,offset,size,link,info,align,entsize=struct.unpack_from("<IIQQQQIIQQ",data,off)
    secs.append(dict(name=name,typ=typ,addr=addr,offset=offset,size=size,link=link,entsize=entsize))
shstr=secs[e_shstrndx]
def sname(n):
    e=data.index(b"\0",shstr["offset"]+n)
    return data[shstr["offset"]+n:e].decode()
for s in secs: s["sname"]=sname(s["name"])
# dynsym + dynstr
dynsym=[s for s in secs if s["sname"]==".dynsym"][0]
dynstr=[s for s in secs if s["sname"]==".dynstr"][0]
def sym_at(i):
    off=dynsym["offset"]+i*24
    st_name,st_info,st_other,st_shndx,st_value,st_size=struct.unpack_from("<IBBHQQ",data,off)
    e=data.index(b"\0",dynstr["offset"]+st_name)
    nm=data[dynstr["offset"]+st_name:e].decode()
    return nm
n=dynsym["size"]//24
syms=[sym_at(i) for i in range(n)]
print("dynsyms:",n)
import re
pat=re.compile(r"time|clock|date|rand|gettim|tv_|syscall|open|read|prop|sysconf",re.I)
hits=[s for s in syms if pat.search(s)]
print("time/rand-ish imports:",hits)
# undefined (imported) syms
undef=[s for s in syms if s]
print("total named:",len(undef))
print("ALL imports:", undef[:200])
