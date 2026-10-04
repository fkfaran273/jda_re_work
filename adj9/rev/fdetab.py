# fdetab.py — FDE function table (table_enc=0x3b datarel sdata4: abs = hdr_va + raw)
import struct,sys,os,bisect
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from elf import ELF
e=ELF(r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so")
hdr=e.byname[".eh_frame_hdr"]
va=hdr["addr"]; b=e.data[hdr["offset"]:hdr["offset"]+hdr["size"]]
fc=struct.unpack_from("<I",b,8)[0]
p=12
starts=set()
for i in range(fc):
    loc,fdep=struct.unpack_from("<ii",b,p)
    starts.add(va+loc)   # datarel base = eh_frame_hdr address
    p+=8
starts=sorted(starts)
_text=e.byname[".text"]
sys.stderr.write("FDE funcs: %d, range %x..%x\n"%(len(starts),starts[0],starts[-1]))
def func_of(addr):
    i=bisect.bisect_right(starts,addr)-1
    return starts[i] if i>=0 else None
def func_range(addr):
    i=bisect.bisect_right(starts,addr)-1
    if i<0: return None,None
    return starts[i], starts[i+1] if i+1<len(starts) else _text["addr"]+_text["size"]
