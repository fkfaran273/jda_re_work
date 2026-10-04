# rsa_xref.py - find adrp+add references to crypto .data strings, and who calls them
import struct, sys
from capstone import *
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

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
text=[s for s in secmap if s[0]==".text"][0]
taddr,toff,tsize=text[1],text[2],text[4]

def v2o(v):
    for sn_,addr,off,link,size in secmap:
        if addr<=v<addr+size and addr!=0:
            return off+(v-addr), sn_
    return None,None

# load decoded strings: vma -> text
decoded={}
for line in open("data_strings_decoded2.txt"):
    p=line.split(None,2)
    if len(p)==3 and p[0].startswith("0x"):
        decoded[int(p[0],16)]=p[2].rstrip("\n")

# entry VAs of interest
targets={
 0x154830:"RSA/ECB/PKCS1Padding",
 0x153794:"RSA",
 0x1537f0:"javax/crypto/Cipher",
 0x153c40:"getPrivate",
 0x153db0:"getCertificateChain",
 0x153a20:"setAttestationChallenge",
 0x154480:"SecretKeySpec",
 0x1547f8:"HmacSHA256",
 0x154810:"~Q[MPV...key2",
 0x154848:"adjust_keys",
 0x154858:"encrypted_key",
 0x154868:"AES",
 0x155138:"/dev/urandom",
 0x153980:"KeyGenParameterSpec$Builder",
 0x153d40:"KeyInfo",
 0x1545a0:"getSigningCertificateHistory",
}
# parse .text with adrp+add tracking
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
code=data[toff:toff+tsize]
adrp={}
refs=[]  # (site_va, string_va, reg)
for ins in md.disasm(code,taddr):
    if ins.mnemonic=="adrp":
        adrp[ins.operands[0].reg]=ins.operands[1].imm
    elif ins.mnemonic=="add" and len(ins.operands)==3 and \
         ins.operands[0].type==ARM64_OP_REG and ins.operands[2].type==ARM64_OP_IMM:
        rd=ins.operands[0].reg; rn=ins.operands[1].reg; imm=ins.operands[2].imm
        if rn in adrp:
            va=adrp[rn]+imm
            if va in targets:
                refs.append((ins.address,va,md.reg_name(rd)))
    elif ins.mnemonic in ("ldr",):
        # adrp+ldr pairs also reference strings sometimes; track adrp+ldr
        pass
    # invalidate reg on write by non-add
    if ins.mnemonic not in ("add","adrp"):
        if len(ins.operands)>=1 and ins.operands[0].type==ARM64_OP_REG:
            adrp.pop(ins.operands[0].reg,None)

byva={}
for site,va,reg in refs:
    byva.setdefault(va,[]).append(site)
for va,label in sorted(targets.items()):
    sites=byva.get(va,[])
    print("0x%x %-28s refs: %d"%(va,label,len(sites)))
    for s in sites:
        print("    called from 0x%x"%s)
