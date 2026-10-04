import sys
sys.path.insert(0,r'C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool')
import adj9_signer as S
elf=S._Elf(S.LIB)
off=elf.vaddr_to_off(0x143f00)
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
data=open(S.LIB,'rb').read()
for i in md.disasm(data[off:off+0x400],0x143f00):
    print('%08x  %-8s %s'%(i.address,i.mnemonic,i.op_str))
