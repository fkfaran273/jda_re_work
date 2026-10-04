import struct
from capstone import *
so="C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data=open(so,"rb").read()
exec(open("rev/plt_names.py").read().split("for k in sorted")[0])
from capstone import *
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
# whole .text bl -> name census
text=[s for s in secmap if s[0]==".text"][0]
md.detail=True
code=data[text[2]:text[2]+text[4]]
import collections
c=collections.Counter()
sites=collections.defaultdict(list)
for ins in md.disasm(code,text[1]):
    if ins.mnemonic=="bl":
        nm=ent2sym.get(ins.operands[0].imm)
        if nm and nm!="?":
            c[nm]+=1
            sites[nm].append(hex(ins.address))
for k,v in c.most_common(50):
    if k in ("time","srand","rand","gettimeofday","clock_gettime","localtime","strftime","fmod","__system_property_get","sscanf","fopen","fread","read","inet_aton","socket","connect","sendto","recvfrom"):
        print(k,v,sites[k][:8])
