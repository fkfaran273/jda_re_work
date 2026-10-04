import sys,os
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import capstone
from elf import ELF
import fdetab,bisect
e=ELF(r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so")
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
for start in (0x147630,0x147734):
    i=bisect.bisect_right(fdetab.starts,start)
    end=fdetab.starts[i] if i<len(fdetab.starts) else start+0x200
    off=e.vaddr_to_off(start)
    print("=== 0x%x..0x%x ==="%(start,end))
    for ins in md.disasm(e.data[off:e.vaddr_to_off(end)],start):
        print("0x%06x %-8s %s"%(ins.address,ins.mnemonic,ins.op_str))
