import struct, re, sys
from capstone import *
LIB=r'C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so'
d=open(LIB,'rb').read()
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
a,b=int(sys.argv[1],16),int(sys.argv[2],16)
for i in md.disasm(d[a:b],a): print("%08x %-8s %s"%(i.address,i.mnemonic,i.op_str))
