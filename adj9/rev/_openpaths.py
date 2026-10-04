#!/usr/bin/env python3
import sys, struct
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
insns=list(md.disasm(data[TO:TO+TS],TA))
idx={i.address:n for n,i in enumerate(insns)}
# section lookup for a VA
def va2off(va):
    for nm,(a,o,s) in secs.items():
        if s and a<=va<a+s and nm not in ('.bss',): return o+(va-a)
    return None
def rd_cstr(off,maxn=64):
    e=data.index(b'\0',off)
    return data[off:min(e,off+maxn)]
def decode_tbl(off):
    # per-entry single-byte XOR: last byte incl NUL is the key
    e=data.index(b'\0',off)
    raw=data[off:e+1]
    k=raw[-1]
    return bytes(b^k for b in raw[:-1])
OPENAT=[0x01c7c8,0x0e1f88,0x0e490c,0x0e4dec,0x13e764]
for site in OPENAT:
    print("==== openat @0x%06x ===="%site)
    i=idx[site]-1; seen=0
    while i>=0 and seen<60:
        ins=insns[i]
        if ins.mnemonic=='bl' or ins.mnemonic=='b': 
            if ins.mnemonic=='b': i-=1; seen+=1; continue
            break
        if ins.mnemonic=='adrp' or ins.mnemonic=='adr':
            print("   0x%06x %-6s %s"%(ins.address,ins.mnemonic,ins.op_str))
        if ins.mnemonic=='add' and ('x1' in ins.op_str.split(',')[0]):
            print("   0x%06x %-6s %s"%(ins.address,ins.mnemonic,ins.op_str))
        i-=1; seen+=1
    print()
