import sys,struct
sys.path.insert(0,r'C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool')
import adj9_signer as S
data=open(S.LIB,'rb').read()
elf=S._Elf(S.LIB)
print('segments:',[(hex(a),hex(b),hex(c)) for a,b,c in elf.segments])
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
targets={0x144074,0x144210}
n=0
for vaddr,hi,off in elf.segments:
    blob=data[off:off+(hi-vaddr)]
    for i in md.disasm(blob,vaddr):
        if i.mnemonic in ('bl','b'):
            n+=1
            ops=i.op_str
            if ops.startswith('#'):
                try: t=int(ops[1:],16)
                except: continue
                if t in targets:
                    print('caller at %08x  %s %s'%(i.address,i.mnemonic,ops))
print('total ins scanned',n)
