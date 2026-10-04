#!/usr/bin/env python3
import sys, glob, os, struct, collections
sys.path.insert(0,'.')
from _fold_exact import data, secs
def sec(n):
    for nm,(a,o,s) in secs.items():
        if nm==n: return a,o,s
ds_a,ds_o,ds_s=sec('.dynsym'); st_a,st_o,st_s=sec('.dynstr')
rp_a,rp_o,rp_s=sec('.rela.plt')
def symname(idx):
    off=ds_o+idx*24; no=struct.unpack_from('<I',data,off)[0]
    return data[st_o+no:data.index(b'\0',st_o+no)].decode()
PLT0=0x1489e0; N=rp_s//24
names=[None]*N
for i in range(N):
    r_off,r_info,_=struct.unpack_from('<QQq',data,rp_o+i*24)
    names[i]=symname(r_info>>32)
PLT_END=PLT0+16*N

base=0x6f0f843000
LO,HI=base+PLT0, base+PLT_END
D='../device/ctxburst_out/ctxburst'
files=sorted(glob.glob(os.path.join(D,'*.bin')))
print("files:",len(files))
cnt=collections.Counter()
for f in files:
    b=open(f,'rb').read()
    for o in range(0,len(b)-8,8):
        v=struct.unpack_from('<Q',b,o)[0]
        if LO<=v<HI:
            idx=(v-base-PLT0)//16
            if 0<=idx<N: cnt[names[idx]]+=1
print("=== PLT return addrs found on stacks (call frequency) ===")
for nm,c in cnt.most_common(50):
    print("  %-28s x%d"%(nm,c))
