#!/usr/bin/env python3
import sys, struct
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
def sec(n):
    for nm,(a,o,s) in secs.items():
        if nm==n: return a,o,s
ds_a,ds_o,ds_s=sec('.dynsym'); st_a,st_o,st_s=sec('.dynstr')
rp_a,rp_o,rp_s=sec('.rela.plt'); pl_a,pl_o,pl_s=sec('.plt')
gp_a,gp_o,gp_s=sec('.got.plt')
def symname(idx):
    off=ds_o+idx*24; no=struct.unpack_from('<I',data,off)[0]
    return data[st_o+no:data.index(b'\0',st_o+no)].decode()
# rela.plt: (got_offset -> name)
rela={}
for i in range(rp_s//24):
    off=rp_o+i*24
    r_off,r_info,_=struct.unpack_from('<QQq',data,off)
    rela[r_off]=symname(r_info>>32)
# disassemble the .plt region and recover, per stub, the GOT slot it loads
stubs={}
cur=None
for i in md.disasm(data[pl_o:pl_o+pl_s],pl_a):
    if i.mnemonic=='adrp' and i.op_str.startswith('x16'):
        cur=i.address
    if i.mnemonic=='ldr' and i.op_str.startswith('x17') and cur is not None:
        # op_str like "x17, [x16, #0x258]"
        try:
            imm=int(i.op_str.split('#')[-1].rstrip(']'),16)
        except: imm=None
        # resolve adrp page
        page=None
        for j in md.disasm(data[pl_o+(cur-pl_a):pl_o+(cur-pl_a)+4],cur):
            page=j.operands[1].imm
        if imm is not None and page is not None:
            stubs[cur]=(page+imm)
        cur=None
print("stub      got_off   name(from rela.plt)")
for s in sorted(stubs):
    go=stubs[s]
    print("0x%06x  0x%06x  %s"%(s,go,rela.get(go,'???')))
print()
print("--- what our live targets resolve to ---")
for t in (0x148a70,0x148a80,0x148b10,0x148b20,0x148b30,0x148c20,0x148c30,0x148c50,0x148c60,0x148c70):
    print("  0x%06x -> %s"%(t, rela.get(stubs.get(t,-1),'???')))
