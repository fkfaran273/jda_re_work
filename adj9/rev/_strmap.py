#!/usr/bin/env python3
import sys, re, collections
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
insns=list(md.disasm(data[TO:TO+TS],TA))
def va2off(va):
    for nm,(a,o,s) in secs.items():
        if s and a<=va<a+s: return o+(va-a),nm
    return None,None
def dec(va,maxn=80):
    o,nm=va2off(va)
    if o is None: return None
    buf=data[o:o+maxn]
    # entry = ciphertext(L-1) || key ; key = last byte ; plaintext all printable
    for L in range(4,min(len(buf),maxn)+1):
        k=buf[L-1]
        d=bytes(c^k for c in buf[:L-1])
        if all(32<=c<127 for c in d): return d.decode()
    return None
refs=collections.defaultdict(set)
last_adrp={}
for i in insns:
    if i.mnemonic=='adrp' and i.op_str.startswith('x'):
        rd=i.op_str.split(',')[0].strip()
        last_adrp[rd]=(i.address,i.operands[1].imm)
    elif i.mnemonic=='add' and i.op_str.count(',')==2:
        parts=[p.strip() for p in i.op_str.split(',')]
        if parts[0].startswith('x') and parts[1]==parts[0] and parts[2].startswith('#'):
            if parts[0] in last_adrp and i.address-last_adrp[parts[0]][0]<=12:
                try: off=int(parts[2][1:],16)
                except: continue
                va=last_adrp[parts[0]][1]+off
                s=dec(va)
                if s: refs[s].add(i.address)
import re as _re
out=[(s,vas) for s,vas in refs.items() if _re.match(r'^[/\w]',s) and (s.startswith('/') or len(s)>6)]
out.sort(key=lambda kv:min(kv[1]))
print("=== decoded static strings (filtered) ===")
for s,vas in out:
    print("  %-56r %s"%(s, ' '.join('0x%06x'%v for v in sorted(vas))))
