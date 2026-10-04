#!/usr/bin/env python3
import sys, struct
sys.path.insert(0,'.')
from _fold_exact import data, secs
def sec(n):
    for nm,(a,o,s) in secs.items():
        if nm==n: return a,o,s
    raise KeyError(n)
ds_a,ds_o,ds_s=sec('.dynsym'); st_a,st_o,st_s=sec('.dynstr')
rp_a,rp_o,rp_s=sec('.rela.plt'); pl_a,pl_o,pl_s=sec('.plt')
N=ds_s//24
def symname(idx):
    off=ds_o+idx*24
    nameoff=struct.unpack_from('<I',data,off)[0]
    return data[st_o+nameoff:data.index(b'\0',st_o+nameoff)].decode()
pltmap={}
n=rp_s//24
for i in range(n):
    off=rp_o+i*24
    r_off,r_info,r_add=struct.unpack_from('<QQq',data,off)
    sym=r_info>>32
    stub=pl_a+16*(i+1)
    pltmap[stub]=(symname(sym), r_off)
print("PLT entries:",n)
for stub in sorted(pltmap):
    nm,go=pltmap[stub]
    print("  0x%06x  %s"%(stub,nm))
print()
print("=== our targets ===")
for t in (0x148c30,0x148c70,0x148b20,0x148c20,0x148a80,0x148b10):
    print("  0x%06x -> %s"%(t, pltmap.get(t,('??',0))[0]))
