# lrand48_test.py — bionic rand()=lrand48; find header as 4 consecutive outputs
import re,glob,struct,json
def parse_events(path):
    lines=open(path,encoding="utf-8",errors="replace").read().splitlines()
    ev=[];cur=None
    for ln in lines:
        m=re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\d+) ts=(\d+)",ln)
        if m:
            cur={"type":m.group(1),"ts":int(m.group(3)),"body":[]}
            ev.append(cur);continue
        if cur is not None:
            if ln.startswith("###ADJ9_END"):cur=None;continue
            cur["body"].append(ln)
    return ev
def field(e,name):
    j="\n".join(e["body"])
    m=re.search(r"(?:^|\s)"+name+r"=([^\s]+)",j,re.M)
    return m.group(1) if m else None
recs=[]
for path in glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/*.log")+glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/device/*.log"):
    pin=None
    for e in parse_events(path):
        if e["type"]=="nsign_in": pin=e["ts"]
        elif e["type"]=="nsign":
            h=field(e,"hex")
            if h: recs.append({"tin":pin,"tout":e["ts"],"hex":h}); pin=None
# dedupe
seen=set();u=[]
for r in recs:
    if r["hex"] in seen: continue
    seen.add(r["hex"]); u.append(r)
print("unique blobs:",len(u))
A,C,M=0x5DEECE66D,0xB,1<<48
def lrand48_stream(seed,n=64):
    s=(seed<<16)|0x330E  # srand48: X0 = (seed<<16)+0x330E
    s&=M-1
    out=[]
    for _ in range(n):
        s=(s*A+C)%M
        out.append(s>>17)
    return out
hdr_hits=0
for r in u:
    w=struct.unpack(">4I",bytes.fromhex(r["hex"])[:16])
    tin=r["tin"] or r["tout"]; tout=r["tout"]
    cands={}
    for lbl,base in [("tin",tin),("tout",tout)]:
        for d in (-1,0,1):
            cands["%s%+d"%(lbl,d)]=base//1000+d
    found=False
    for lbl,seed in cands.items():
        st=lrand48_stream(seed,80)
        for k in range(77):
            if tuple(st[k:k+4])==w:
                print("HIT %s seed=%d(%s) draw#%d..%d  blob=%s"%(r["hex"][:8],seed,lbl,k,k+3,r["hex"][:16]))
                found=True;hdr_hits+=1;break
        if found: break
print("lrand48 hits: %d/%d"%(hdr_hits,len(u)))
