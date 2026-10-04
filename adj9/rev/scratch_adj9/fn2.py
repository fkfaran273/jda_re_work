import sys
sys.path.insert(0,r'C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool')
import adj9_signer as S
data=open(S.LIB,'rb').read()
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
def dis(va,n):
    for i in md.disasm(data[va:va+n],va):
        print('%08x  %-8s %s'%(i.address,i.mnemonic,i.op_str))
dis(0x1437d4,0x20)
print('...')
dis(0x143ae8,0x40)
print('=== 0x1441e4 wrapper ===')
dis(0x1441e4,0x40)
print('=== 0x143b20 rest (0x143c80) ===')
dis(0x143c80,0x10)
