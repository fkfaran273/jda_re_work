#!/usr/bin/env python3
"""find bl/b targets -> callers, for a set of target VAs"""
import sys, struct
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
# build text image
for nm,(a,o,s) in secs.items():
    if nm == '.text':
        TA, TO, TS = a, o, s
        break
code = data[TO:TO+TS]
# decode all insns once
insns = list(md.disasm(code, TA))

def find_hub_start(target):
    # walk back for a prologue: stp x29,x30,[sp,#-imm]!  or sub sp,sp,#imm
    idx = None
    for i,ins in enumerate(insns):
        if ins.address == target: idx = i; break
    if idx is None: return None
    for j in range(idx, max(0, idx-2000), -1):
        m = insns[j].mnemonic
        op = insns[j].op_str
        if m == 'stp' and 'x29, x30, [sp, #-' in op and ']!' in op:
            return insns[j].address
        if m == 'sub' and op.startswith('sp, sp, #') and j+1 < len(insns) and insns[j+1].mnemonic=='stp' and 'x29, x30' in insns[j+1].op_str:
            return insns[j].address
    return None

def callers_of(target):
    out = []
    for ins in insns:
        if ins.mnemonic in ('bl','b'):
            op = ins.op_str
            if op.startswith('#'):
                try: t = int(op[1:], 16)
                except: continue
                if t == target: out.append((ins.address, ins.mnemonic))
    return out

hub = find_hub_start(0xdb160)
print('hub function start containing 0xdb160 =', hex(hub) if hub else None)
for tgt,label in [(0x143794,'ctx_wrapper'),(hub,'hub'),(0xdb1cc,'nSign 0xdb1cc')]:
    if tgt is None: continue
    cs = callers_of(tgt)
    print('callers of %s (0x%x): %d -> %s' % (label, tgt, len(cs), [hex(a) for a,_ in cs][:12]))
