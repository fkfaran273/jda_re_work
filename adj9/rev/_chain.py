#!/usr/bin/env python3
import sys
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
insns=list(md.disasm(data[TO:TO+TS], TA))
# map addr->index
addr2i={ins.address:i for i,ins in enumerate(insns)}
def func_start(target):
    i=addr2i.get(target)
    if i is None: return None
    for j in range(i, max(0,i-4000), -1):
        m,op=insns[j].mnemonic,insns[j].op_str
        if m=='stp' and 'x29, x30, [sp, #-' in op and ']!' in op: return insns[j].address
        if m=='sub' and op.startswith('sp, sp, #') and j+1<len(insns) and insns[j+1].mnemonic=='stp' and 'x29, x30' in insns[j+1].op_str: return insns[j].address
    return None
def callers(target):
    out=[]
    for ins in insns:
        if ins.mnemonic in ('bl','b') and ins.op_str.startswith('#'):
            try: t=int(ins.op_str[1:],16)
            except: continue
            if t==target: out.append(ins.address)
    return out
def walk(start, depth=0, seen=None):
    if seen is None: seen=set()
    fs=func_start(start) or start
    if fs in seen or depth>6: return
    seen.add(fs)
    cs=callers(fs)
    print('%sfunc 0x%x  (asked 0x%x)  callers=%s' % ('  '*depth, fs, start, [hex(c) for c in cs][:8]))
    for c in cs[:8]:
        walk(c, depth+1, seen)
print('--- chain from hub 0xda6b8 upward ---')
walk(0xda6b8)
print()
print('--- chain from nSign 0xdb1cc targets ---')
for t in (0xe2be0, 0x95fc4):
    fs=func_start(t)
    print('nSign calls 0x%x -> func 0x%x' % (t, fs or -1))
    walk(t, 1, set())
