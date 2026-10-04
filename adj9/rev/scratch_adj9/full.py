import sys
sys.path.insert(0,r'C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool')
import adj9_signer as S
data=open(S.LIB,'rb').read()
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
def dis(va,n):
    for i in md.disasm(data[va:va+n],va):
        print('%08x  %-8s %s'%(i.address,i.mnemonic,i.op_str))
print('=== 0x143b20 helper ===')
dis(0x143b20,0x160)
print('=== 0x1438b4 dispatcher entry ===')
dis(0x143880,0x60)
