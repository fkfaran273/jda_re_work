# Sweep all (row,blob) pairings, seed=second, #7 in {unpadded, len, len-1..len-3}
# region from each row's S. Report any 48/48.
import sys, os, struct, json
sys.path.insert(0, os.path.abspath('../adj9_tool'))
sys.path.insert(0, os.path.abspath('.'))
import adj9_signer as A
from fin_vm2 import FinEx
from collections import defaultdict
VA_ORDER=[0,9,8,4,2,7,10,5,1,6,3]
D8=bytes.fromhex(A.D8_HEX); D9=bytes.fromhex(A.D9_HEX)
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
def build(region,d10_raw,unpadded):
    d0w,d2v,d4w=region
    n10=len(d10_raw)//4; data10=d10_raw[:n10*4]
    by={0:(36,be(d0w)),9:(5,D9),8:(4,D8),4:(8,be(d4w)),2:(1,be([d2v])),
        7:(1,be([unpadded])),10:(n10,data10),5:(1,be([0])),1:(0,b""),6:(1,be([0])),3:(0,b"")}
    return [(by[i][0],0,by[i][1]) for i in VA_ORDER]
rows=json.load(open('../device/rows.json'))['rows']
blobs={'A':bytes.fromhex(open('../device/blob_1790269484963.hex').read().strip()),
       'B':bytes.fromhex(open('../device/blob_1790269485579.hex').read().strip())}
signsec={'A':1790269484,'B':1790269485}
for ri,row in enumerate(rows):
    S_=row['S']; d10=bytes.fromhex(row['d10_hex']); region=A.region(S_,0)
    for bn,blob in blobs.items():
        sec=signsec[bn]
        for unp in sorted({len(d10),len(d10)-1,len(d10)-2,len(d10)-3}):
            descs=build(region,d10,unp)
            st,iters,best,tot,diff,sink=run(sec,descs,blob)
            tag=" <<<<< BYTE-EXACT" if best==tot else ""
            print("row%d->blob%s seed=sec=%d #7=%-4d match=%d/%d diff=%s%s"%(
                ri,bn,sec,unp,best,tot,diff[:6],tag)); sys.stdout.flush()
print("SWEEP DONE")
