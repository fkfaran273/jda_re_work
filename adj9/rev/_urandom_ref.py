#!/usr/bin/env python3
import sys, struct
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
insns=list(md.disasm(data[TO:TO+TS],TA))
TARGET=0x155138   # "/dev/urandom"
print("=== adr/adrp+add refs to 0x%06x ==="%TARGET)
last={}
for i in insns:
    if i.mnemonic in ('adrp',) and i.op_str.startswith('x'):
        last[i.op_str.split(',')[0].strip()]=i.operands[1].imm
    if i.mnemonic=='adr' and i.operands[1].type==2 and i.operands[1].imm==TARGET:
        print("  adr  @0x%06x"%i.address)
    if i.mnemonic=='add' and i.op_str.count(',')==2:
        p=[q.strip() for q in i.op_str.split(',')]
        if p[0].startswith('x') and p[1]==p[0] and p[2].startswith('#') and p[0] in last:
            try: va=last[p[0]]+int(p[2][1:],16)
            except: continue
            if va==TARGET: print("  adrp+add @0x%06x"%i.address)
    if i.mnemonic=='adrp' and i.operands[1].imm==TARGET: print("  adrp-page @0x%06x"%i.address)
print()
print("=== pointer values == 0x155138 in data sections ===")
for nm,(a,o,s) in secs.items():
    if nm in ('.data.rel.ro','.data','.bss','.got.plt','.got'):
        if nm=='.bss': continue
        blob=data[o:o+s]
        for j in range(0,len(blob)-8,8):
            if struct.unpack_from('<Q',blob,j)[0]==TARGET:
                print("  %s @va 0x%06x"%(nm,a+j))
print()
print("=== code around 0x0091d8 (AdjustSigner ref) ===")
for i in insns:
    if 0x91c0<=i.address<=0x9220: print("  0x%06x  %-8s %s"%(i.address,i.mnemonic,i.op_str))
