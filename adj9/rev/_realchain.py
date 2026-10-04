#!/usr/bin/env python3
import sys, glob, os, struct, collections
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
insns=list(md.disasm(data[TO:TO+TS],TA))
# valid return addresses = addr+4 for every bl
ret=set()
bl_at={}
for i in insns:
    if i.mnemonic=='bl':
        ret.add(i.address+4); bl_at[i.address+4]=i.op_str
print('valid bl return addrs in lib:',len(ret))
base=0x6f0f7ef000   # from ctxburst maps.41 text 6f0f843000 - 0x54000
D='../device/ctxburst_out/ctxburst'
files=[f for f in glob.glob(os.path.join(D,'*.bin')) if '-17126.bin' in f]
print('oracle dumps:',len(files))
c=collections.Counter(); frames=collections.Counter()
for f in files:
    b=open(f,'rb').read()
    for o in range(0,len(b)-8,8):
        v=struct.unpack_from('<Q',b,o)[0]
        if base<=v<base+0x1490000:
            off=v-base
            if off in ret:
                c[off]+=1; frames[os.path.basename(f)]+=1
print('distinct TRUE return addrs:',len(c))
for off,n in c.most_common(30): print('  0x%06x  x%d'%(off,n))
