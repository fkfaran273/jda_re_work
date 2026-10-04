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
def callers(f):
    out=[]
    for c in (f-4,f,f+4): out+=bl.get(c,[])
    return sorted(set(out))
print("=== callers of fn 0x1c230 (file reader) ===")
print("  ", ' '.join('0x%06x'%c for c in callers(0x1c230)) or '-')
print()
print("=== full disasm fn 0x1c230 .. 0x1c8d0 ===")
for i in insns:
    if 0x1c230<=i.address<=0x1c8d0:
        print("  0x%06x  %-8s %s"%(i.address,i.mnemonic,i.op_str))
