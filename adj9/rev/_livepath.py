#!/usr/bin/env python3
import sys, struct, collections
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True

for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
text=data[TO:TO+TS]
insns=list(md.disasm(text,TA))
byaddr={i.address:i for i in insns}
bl_targets=collections.defaultdict(list)
for i in insns:
    if i.mnemonic=='bl' and i.operands and i.operands[0].type==2:
        bl_targets[i.operands[0].imm].append(i.address)

# function starts: prologue heuristics
def is_prologue(i):
    m=i.mnemonic; ops=i.op_str
    if m=='stp' and 'x29, x30' in ops and '[sp, #-' in ops: return True
    if m=='sub' and ops.startswith('sp, sp, #'): return True
    if m=='stp' and 'x29, x30' in ops: return True
    return False
starts=sorted(i.address for i in insns if is_prologue(i))
# also seed with bl targets (functions often start there)
allstarts=sorted(set(starts)|{t for t in bl_targets})
def func_of(a):
    lo,hi=0,len(allstarts)-1; best=None
    for s in allstarts:
        if s<=a: best=s
        else: break
    return best

TARGETS=[0x0e4bf4,0x0e3c54,0x0e431c,0x0e2904,0x0e260c,0x0e2b74,
         0x0299f4,0x039aa4,0x13dec4,0x0db89c,0x01c8b8]
print("=== live return sites -> containing fn ===")
for r in TARGETS:
    call=r-4
    fs=func_of(call)
    ci=byaddr.get(call)
    tgt=None
    if ci and ci.mnemonic=='bl' and ci.operands and ci.operands[0].type==2:
        tgt=ci.operands[0].imm
    print("ret 0x%06x  in fn 0x%06x  bl@0x%06x -> 0x%s"%(r,fs,call,('%06x'%tgt) if tgt else '?'))

print()
print("=== function starts near the hot cluster 0xe2xxx-0xe5xxx ===")
for s in allstarts:
    if 0x0e2000<=s<=0x0e6000: print("  fn 0x%06x"%s)
print()
print("=== callers of key fns ===")
for f in sorted(set(func_of(r-4) for r in TARGETS)):
    callers=[c for c in bl_targets.get(f,[]) if True]
    print("fn 0x%06x  direct-bl callers: %s"%(f, ' '.join('0x%06x'%c for c in callers[:8])))
