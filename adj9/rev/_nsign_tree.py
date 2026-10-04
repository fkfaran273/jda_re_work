#!/usr/bin/env python3
import sys, collections
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
insns=list(md.disasm(data[TO:TO+TS],TA))
idx={i.address:n for n,i in enumerate(insns)}
bl=collections.defaultdict(list)
for i in insns:
    if i.mnemonic=='bl' and i.operands and i.operands[0].type==2:
        bl[i.operands[0].imm].append(i.address)
def fname(a):
    if 0x1489e0<=a<0x148e60:
        # PLT: resolve name lazily via exported map file if present
        return 'PLT'
    return ''
NSTART,NEND=0xdb1cc,0xdbe40
print("=== nSign(0x%x..0x%x) direct bl targets ==="%(NSTART,NEND))
tgts=sorted({i.operands[0].imm for i in insns if NSTART<=i.address<NEND and i.mnemonic=='bl' and i.operands and i.operands[0].type==2})
for t in tgts:
    sites=bl[t]
    inside='IN-nSign' if NSTART<=t<NEND else ''
    print("  -> 0x%06x  (%d calls) %s"%(t,len(sites),inside))
print()
print("=== does anything call 0xdb160 / 0x143794 / 0x1437b8 / get8random? ===")
for f in (0xdb160,0x143794,0x1437b8,0x13e0e4,0x13de98,0x13dfd0,0x143c88,0x144214):
    cs=[]
    for c in (f-4,f,f+4,f-8,f-12): cs+=bl.get(c,[])
    print("  0x%06x callers: %s"%(f,' '.join('0x%06x'%x for x in sorted(set(cs))) or '-'))
