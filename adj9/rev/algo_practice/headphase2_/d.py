import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
SO = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
data = open(SO,"rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
def dis(a,b):
    for i in md.disasm(data[a:b], a):
        print("%08x  %-10s %s" % (i.address, i.mnemonic, i.op_str))
a=int(sys.argv[1],16); b=int(sys.argv[2],16); dis(a,b)
