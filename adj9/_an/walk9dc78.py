import sys,re
sys.path.insert(0,r'C:\Users\Apps\AppData\Local\Temp\adj9')
import an
from capstone import *
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
LO,HI=0x9dc78,0x9e0c0
L=list(md.disasm(an.D[LO:HI],LO))
def num(s):
    m=re.search(r'#(0x[0-9a-fA-F]+|\d+)',s); return int(m.group(1),16) if m else None
V={}; tab={}
for k,i in enumerate(L):
    m,o=i.mnemonic,i.op_str; p=[q.strip() for q in o.split(',')]
    if m=='mov' and p[0].startswith('x') and p[1].startswith('#'): V[p[0]]=num(o)
    elif m=='movk' and p[0].startswith('x'):
        mm=re.search(r'lsl\s*#(\d+)',o); sh=int(mm.group(1)) if mm else 0
        V[p[0]]=((V.get(p[0],0))&~(0xffff<<sh))|((num(o)&0xffff)<<sh)
    elif m=='cmp' and len(p)==2 and p[1] in V and p[0] in V:
        for j in L[k+1:k+5]:
            if j.mnemonic=='b.eq':
                tab.setdefault((V[p[0]],V[p[1]]),int(j.op_str.split('#')[1],16)); break
for (a,b),t in sorted(tab.items(),key=lambda kv:kv[1]):
    print('  state=%#018x  cmp=%#018x -> %#x'%(a,b,t))
print()
# entry: x21 = csel(x9,x19,eq) ; x19=0xa1009045ee3af5ac if x2!=0
print('entry state (H!=null) = %#018x'%0xa1009045ee3af5ac)
print('entry state (H==null) = %#018x'%0x63b58922  )
