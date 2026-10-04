#!/usr/bin/env python3
import sys, collections
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
def func_start(a):
    # scan back for stp x29,x30 or sub sp,sp
    i=byaddr.get(a)
    n=None
    cur=a
    for j in range(len(insns)):
        ins=insns[byaddr[a]-j] if byaddr[a]-j>=0 else None
        if ins is None: break
        if (ins.mnemonic=='stp' and 'x29, x30' in ins.op_str) or (ins.mnemonic=='sub' and ins.op_str.startswith('sp, sp')):
            return ins.address
    return None
print("=== hub region 0xda6b8..0xdb1cc : bl targets ===")
tg=sorted({i.operands[0].imm for i in insns if 0xda6b8<=i.address<0xdb1cc and i.mnemonic=='bl' and i.operands and i.operands[0].type==2})
for t in tg: print("  -> 0x%06x (%d)"%(t,len(bl[t])))
print()
print("=== fn start containing 0xdb160 / 0xda97c / 0xdb1cc ===")
for a in (0xdb160,0xda97c,0xdb1cc,0x13de90,0x13d874):
    print("  0x%06x -> start 0x%s"%(a, ('%06x'%func_start(a)) if func_start(a) else '?'))
print()
print("=== who calls 0x13de90 (clock helper) and 0x13d874 ===")
for f in (0x13de90,0x13d874):
    cs=[]
    for c in (f-4,f,f+4): cs+=bl.get(c,[])
    print("  0x%06x: %s"%(f,' '.join('0x%06x'%x for x in sorted(set(cs)))))
print()
print("=== disasm 0x13de90..0x13df10 (clock helper) ===")
for i in insns:
    if 0x13de90<=i.address<=0x13df10: print("  0x%06x  %-8s %s"%(i.address,i.mnemonic,i.op_str))
