#!/usr/bin/env python3
import sys, glob, os, struct, collections
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
insns=list(md.disasm(data[TO:TO+TS],TA))
ret={i.address+4 for i in insns if i.mnemonic=='bl'}
print('.text VA range: 0x%x..0x%x ; bl return addrs: %d'%(TA,TA+TS,len(ret)))
base=0x6f0f843000          # mapping start = lib VA 0
LO,HI=base+TA, base+TA+TS
D='../device/ctxburst_out/ctxburst'
files=sorted(glob.glob(os.path.join(D,'*.bin')))
c=collections.Counter()
for f in files:
    b=open(f,'rb').read()
    for o in range(0,len(b)-8,8):
        v=struct.unpack_from('<Q',b,o)[0]
        if LO<=v<HI and (v-base) in ret: c[v-base]+=1
print('files scanned:',len(files))
print('distinct TRUE return addrs:',len(c))
for off,n in c.most_common(30): print('   VA 0x%06x  x%d'%(off,n))
# also: specific ctx-path probes
for t in (0xdb164,0x1437c8,0x1437bc,0x143794,0x143c88,0x144214,0x1441e4,0xdb1cc,0xe2be4,0x95fc8,0xdb220,0xdb250):
    n=sum(open(f,'rb').read().count(struct.pack('<Q',base+t)) for f in files)
    if n: print('  probe VA 0x%06x hits=%d'%(t,n))
