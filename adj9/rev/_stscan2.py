#!/usr/bin/env python3
"""Derive libsigner base from the stack dumps (V mod 0x1000 must match a
bl-return VA mod 0x1000) then report the live call chain + ctx probes."""
import sys, glob, os, struct, collections
import numpy as np
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
insns=list(md.disasm(data[TO:TO+TS],TA))
ret=sorted({i.address+4 for i in insns if i.mnemonic=='bl'})
retmod=collections.defaultdict(list)
for r in ret: retmod[r & 0xfff].append(r)
files=sorted(glob.glob(os.path.join(os.path.dirname(__file__),'..','device','st_out','*.bin')))
print("files:",len(files))
vals=[]
for f in files:
    b=open(f,'rb').read()
    a=np.frombuffer(b[:len(b)//8*8],dtype='<u8')
    m=(a>=0x6000000000)&(a<0x8000000000)
    vals.append(a[m])
allv=np.concatenate(vals) if vals else np.array([],dtype='<u8')
print("plausible code ptrs:",len(allv))
votes=collections.Counter()
for v in allv:
    v=int(v)
    for r in retmod.get(v & 0xfff, ()):
        votes[v-r]+=1
print("=== top candidate bases ===")
for b,n in votes.most_common(5): print("   base 0x%x  votes=%d"%(b,n))
base=votes.most_common(1)[0][0]
print("chosen base = 0x%x"%base)
LO,HI=base+TA,base+TA+TS
cnt=collections.Counter()
for a in allv:
    v=int(a)
    if LO<=v<HI:
        off=v-base
        if off in set(ret): cnt[off]+=1
print("=== TRUE return addrs (top 30) ===")
for off,n in cnt.most_common(30): print("   VA 0x%06x  x%d"%(off,n))
print()
print("=== ctx-path probes ===")
for t in (0xdb164,0x1437c8,0x1437bc,0x143794,0x1437b8,0x13e0e4,0x143c88,0x144214,0x1441e4,0x13dfd0,0xdb1cc,0xda97c,0x13de90,0xe3144):
    n=sum(open(f,'rb').read().count(struct.pack('<Q',base+t)) for f in files)
    print("   VA 0x%06x hits=%d"%(t,n))
