#!/usr/bin/env python3
import sys
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
insns=list(md.disasm(data[TO:TO+TS],TA))
by={i.address:i for i in insns}
def show(tag,va,n=10):
    print('\n== %s @0x%x =='%(tag,va))
    # print a few insns before/after
    st=va-4*n
    for ins in insns:
        if st<=ins.address<=va+4*n:
            mark=' <== ret-addr' if ins.address==va else ''
            print('  0x%06x  %-8s %s%s'%(ins.address,ins.mnemonic,ins.op_str,mark))
    # what calls the function containing va?
def fstart(va):
    i=[k for k,x in enumerate(insns) if x.address==va]
    if not i: return None
    i=i[0]
    for j in range(i,max(0,i-6000),-1):
        m,op=insns[j].mnemonic,insns[j].op_str
        if m=='stp' and 'x29, x30, [sp, #-' in op and ']!' in op: return insns[j].address
        if m=='sub' and op.startswith('sp, sp, #') and j+1<len(insns) and insns[j+1].mnemonic=='stp' and 'x29, x30' in insns[j+1].op_str: return insns[j].address
    return None
for tag,va in [('0xeefec',0xeefec),('0x6fc70',0x6fc70),('0x7d9f4',0x7d9f4)]:
    show(tag,va,6)
    print('   func start containing it =', hex(fstart(va) or 0))
