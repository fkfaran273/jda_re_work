import sys, os, struct, json
sys.path.insert(0, os.path.abspath('../adj9_tool'))
sys.path.insert(0, os.path.abspath('.'))
import adj9_signer as A
from fin_vm2 import FinEx
from collections import defaultdict
VA_ORDER=[0,9,8,4,2,7,10,5,1,6,3]
def be(w): return b"".join(struct.pack(">I",x&0xFFFFFFFF) for x in w)
def run(seed,descs,target):
    ex=FinEx(seed,descs); st=ex.run(max_steps=12_000_000)
    last={}
    for (sva,n,v) in ex.emit_trace: last[(sva&0xFFFFFFFFFFFF,n&0xFFFFFFFF)]=v&0xFFFFFFFF
    bys=defaultdict(dict)
    for (sva,n),v in last.items(): bys[sva][n]=v
    tgt=[struct.unpack_from(">I",target,4*j)[0] for j in range(len(target)//4)]
    best,bs=-1,None
    for sva,m in bys.items():
        c=sum(1 for j,v in enumerate(tgt) if m.get(j)==v)
        if c>best: best,bs=c,sva
    m=bys[bs]; diff=[j for j in range(len(tgt)) if m.get(j)!=tgt[j]]
    return st,ex.steps,best,len(tgt),diff,bs
# use CAPTURED descriptors for old row0 -> validates harness itself
ph3=json.load(open('pair_h3.json')); asg=json.load(open('all_signings.json'))
for i in [0,1]:
    r,a=ph3[i],asg[i]
    blob=bytes.fromhex(r['blob']); sec=r['second']
    by={}
    for bi in VA_ORDER:
        hx=a.get('d%d'%bi,'')
        data=bytes.fromhex(hx) if hx else b''
        by[bi]=(len(data)//4,0,data[:(len(data)//4)*4])
    descs=[by[bi] for bi in VA_ORDER]
    st,iters,best,tot,diff,sink=run(sec,descs,blob)
    print("old row%d sec=%d CAPTURED-descs seed=second: st=%s iters=%d match=%d/%d diff=%s"%(
        i,sec,st,iters,best,tot,diff[:8]))
    if best==tot: print("   HARNESS VALIDATED 48/48 sink=0x%x"%sink)
