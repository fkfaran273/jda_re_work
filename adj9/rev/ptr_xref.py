# ptr_xref.py - find relocated pointer slots targeting crypto strings, then xrefs to slots
import struct
from capstone import *
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

so="C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data=open(so,"rb").read()
e_shoff=struct.unpack_from("<Q",data,0x28)[0]
e_shentsize=struct.unpack_from("<H",data,0x3a)[0]
e_shnum=struct.unpack_from("<H",data,0x3c)[0]
e_shstrndx=struct.unpack_from("<H",data,0x3e)[0]
secs=[]
for i in range(e_shnum):
    off=e_shoff+i*e_shentsize
    name,typ,flags,addr,offset,size,link,info,align,entsize=struct.unpack_from("<IIQQQQIIQQ",data,off)
    secs.append((name,typ,flags,addr,offset,size,link,info,align,entsize))
shstr=secs[e_shstrndx]
def sname(n):
    e=data.index(b"\0",shstr[4]+n)
    return data[shstr[4]+n:e].decode()
secmap=[(sname(s[0]),s[3],s[4],s[6],s[5]) for s in secs]
byname={s[0]:s for s in secmap}
text=byname[".text"]; taddr,toff,tsize=text[1],text[2],text[4]

def v2o(v):
    for sn_,addr,off,link,size in secmap:
        if addr<=v<addr+size and addr!=0:
            return off+(v-addr), sn_
    return None,None

# parse .rela.dyn: R_AARCH64_RELATIVE (type 1027) addend -> slot vma
rela=byname.get(".rela.dyn")
slotmap={}  # addend(string va) -> set of slot vmas
if rela:
    roff,rsize=rela[2],rela[4]
    n=rsize//24
    for i in range(n):
        off,info,add=struct.unpack_from("<QQq",data,roff+i*24)
        if info&0xffffffff==1027:  # R_AARCH64_RELATIVE
            slotmap.setdefault(add,set()).add(off)

targets={
 0x154830:"RSA/ECB/PKCS1Padding",0x153794:"RSA",0x1537f0:"Cipher",
 0x153c40:"getPrivate",0x153db0:"getCertificateChain",0x153a20:"setAttestChallenge",
 0x154480:"SecretKeySpec",0x1547f8:"HmacSHA256",0x154810:"key2blob",
 0x154848:"adjust_keys",0x154858:"encrypted_key",0x154868:"AES",
 0x155138:"/dev/urandom",0x153980:"KeyGenParmSpec",0x153d40:"KeyInfo",
 0x1545a0:"getSigningCertHistory",0x151cfc:"adj9",
}
for va,label in sorted(targets.items()):
    slots=slotmap.get(va,set())
    print("0x%x %-26s slots: %s"%(va,label,",".join(hex(s) for s in sorted(slots)) or "NONE"))
