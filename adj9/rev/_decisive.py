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
def descs_from_captured(rec):
    by={}
    for did_s,d in rec['desc'].items():
        did=int(did_s); hx=d['hex']
        data=bytes.fromhex(hx) if hx else b''
        n10=len(data)//4
        by[did]=(n10,0,data[:n10*4])
    return [by[i] for i in VA_ORDER]
def descs_from_region(region, d10_raw, unpadded):
    d0w,d2v,d4w=region
    n10=len(d10_raw)//4; data10=d10_raw[:n10*4]
    D8=bytes.fromhex(A.D8_HEX); D9=bytes.fromhex(A.D9_HEX)
    by={0:(36,be(d0w)),9:(5,D9),8:(4,D8),4:(8,be(d4w)),2:(1,be([d2v])),
        7:(1,be([unpadded])),10:(n10,data10),5:(1,be([0])),1:(0,b""),6:(1,be([0])),3:(0,b"")}
    return [by[i] for i in VA_ORDER]

rows=json.load(open('../device/rows_full.json'))['rows']
blobs={1790272711:bytes.fromhex(open('../device/nblob_1790272711.hex').read().strip()),
       1790272712:bytes.fromhex(open('../device/nblob_1790272712.hex').read().strip())}

for ri,row in enumerate(rows):
    S_=row['S']
    # match to a blob by header second == row second (frida second == sign second here)
    sec=row['second']
    if sec not in blobs:
        print("row%d sec=%d no blob (skip)"%(ri,sec)); continue
    blob=blobs[sec]
    # region comparison
    cap_region=bytes.fromhex(row['desc']['0']['hex'])+bytes.fromhex(row['desc']['2']['hex'])+bytes.fromhex(row['desc']['4']['hex'])
    d0w,d2v,d4w=A.region(S_,0)
    reg_region=be(list(d0w))+be([d2v])+be(list(d4w))
    reg_ok = (cap_region==reg_region)
    d10=bytes.fromhex(row['d10_hex']); unp=len(d10.rstrip(b'\x00'))
    # captured #7
    cap7=int.from_bytes(bytes.fromhex(row['desc']['7']['hex']),'big')
    print("="*72)
    print("row%d S=0x%08x sec=%d  region(captured)==region(S,0): %s  #7_cap=%d unpadded=%d"%(
        ri,S_,sec,reg_ok,cap7,unp))
    if not reg_ok:
        for k in range(0,len(cap_region),4):
            if cap_region[k:k+4]!=reg_region[k:k+4]:
                print("   region first diff word %d: cap=%s derived=%s"%(k//4,cap_region[k:k+4].hex(),reg_region[k:k+4].hex()));break
    for label,descs in (("CAPTURED-plane",descs_from_captured(row)),
                        ("region(S,0)+d10",descs_from_region(A.region(S_,0),d10,unp))):
        st,iters,best,tot,diff,sink=run(sec,descs,blob)
        tag="  <<<<<< 192-BYTE BYTE-EXACT" if best==tot else ""
        print("   %-16s st=%s iters=%d match=%d/%d diff=%s%s"%(label,st,iters,best,tot,diff[:8],tag))
        if best==tot: print("        SINK=0x%x CONFIRMED"%sink)
        sys.stdout.flush()
