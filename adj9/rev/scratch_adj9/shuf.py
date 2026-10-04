import sys
sys.path.insert(0,r'C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool')
import adj9_signer as S
data=open(S.LIB,'rb').read()
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
def dis(va,n):
    for i in md.disasm(data[va:va+n],va):
        print('%08x  %-8s %s'%(i.address,i.mnemonic,i.op_str))
print('=== 0x143b20 full, incl 0x143c80..0x143c88 and 0x143c88 shuffle head ===')
dis(0x143b20,0x168)
print('=== 0x143c88 shuffle ===')
dis(0x143c88,0x110)
