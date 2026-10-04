#!/usr/bin/env python3
import sys, struct, collections
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
insns=list(md.disasm(data[TO:TO+TS],TA))
byaddr={i.address:i for i in insns}
bl=collections.defaultdict(list)
for i in insns:
    if i.mnemonic=='bl' and i.operands and i.operands[0].type==2:
        bl[i.operands[0].imm].append(i.address)

def callers_of(f):
    out=[]
    for cand in (f-4,f,f+4,f-8):
        out+=bl.get(cand,[])
    return sorted(set(out))

FNS=[0x0e4b8c,0x0e3148,0x0e26d4,0x0e2518,0x0e294c,0x029750,0x0334b8,
     0x13de98,0x0db1dc,0x01c230,0x0da97c,0x028980,0x0e2514,0x0db1cc]
print("=== callers (bl to entry +/-) ===")
for f in FNS:
    cs=callers_of(f)
    print("fn 0x%06x  callers: %s"%(f,' '.join('0x%06x'%c for c in cs[:10]) or '-'))

print()
print("=== disasm head of each live fn (18 insns) ===")
for f in FNS:
    print("---- fn 0x%06x ----"%f)
    n=0
    for i in insns:
        if i.address<f: continue
        if i.address>f+0x90: break
        print("   0x%06x  %-8s %s"%(i.address,i.mnemonic,i.op_str))
        n+=1
        if n>=18: break
