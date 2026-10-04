#!/usr/bin/env python3
"""Scan the freshly captured oracle-thread stacks for the ctx/fold call chain."""
import sys, glob, os, struct, collections
import numpy as np
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
insns=list(md.disasm(data[TO:TO+TS],TA))
ret={i.address+4 for i in insns if i.mnemonic=='bl'}
# libsigner base: find from the dumps themselves is impossible; use the VA->lib mapping
# we know libbase = start of r-xp mapping whose file offset is 0x54000. We scan for
# *any* 8-byte value V with (V & 0xfff) matching a known VA low bits and V-base in text.
# Simpler: the stacks are 0x6f07xxxxxx; libsigner r-xp in this process -> read maps.
maps=open(os.path.join(os.path.dirname(__file__),'st_maps.txt')).read()
base=None
for line in maps.splitlines():
    f=line.split()
    if len(f)>=6 and f[1].startswith('r-x') and f[2]=='00540000':
        base=int(f[0].split('-')[0],16); break
if base is None:
    for line in maps.splitlines():
        f=line.split()
        if len(f)>=6 and 'libsigner.so' in line and f[1].startswith('r-x'):
            base=int(f[0].split('-')[0],16); break
print("libsigner r-xp base = 0x%x"%(base or 0))
LO,HI=base+TA, base+TA+TS
cnt=collections.Counter()
files=sorted(glob.glob(os.path.join(os.path.dirname(__file__),'st_out','*.bin')))
print("files:",len(files))
anchors=0
for f in files:
    b=open(f,'rb').read()
    a=np.frombuffer(b[:len(b)//8*8],dtype='<u8')
    m=(a>=LO)&(a<HI)
    for v in a[m]:
        off=int(v)-base
        if off in ret: cnt[off]+=1
print("=== TRUE return addrs on oracle stacks ===")
for off,n in cnt.most_common(40): print("   VA 0x%06x  x%d"%(off,n))
print()
print("=== ctx-path probes ===")
for t in (0xdb164,0x1437c8,0x1437bc,0x143794,0x1437b8,0x13e0e4,0x143c88,0x144214,0x1441e4,0x13dfd0,0xdb1cc,0xda97c,0x13de90):
    n=0
    for f in files:
        b=open(f,'rb').read()
        n+=b.count(struct.pack('<Q',base+t))
    print("   VA 0x%06x hits=%d"%(t,n))
