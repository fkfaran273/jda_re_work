import sys,struct
sys.path.insert(0,r'C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool')
import adj9_signer as S
data=open(S.LIB,'rb').read()
elf=S._Elf(S.LIB)
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
# decode whole exec segments and find bl/ b to 0x144074 (and 0x144210 tail call)
targets={0x144074,0x144210}
for vaddr,hi,off in elf.segments:
    if vaddr>=0x200000: continue
    blob=data[off:off+(hi-vaddr)]
    for i in md.disasm(blob,vaddr):
        if i.mnemonic in ('bl','b') and i.op_str.startswith('#0x'):
            t=int(i.op_str[1:],16)
            if t in targets:
                print('caller at %08x  %s %s'%(i.address,i.mnemonic,i.op_str))
