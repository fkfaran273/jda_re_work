# header_crack.py — brute-force header construction against known (seed-second, header) pairs
import re,glob,struct,base64
def parse_events(path):
    lines=open(path,encoding="utf-8",errors="replace").read().splitlines()
    ev=[];cur=None
    for ln in lines:
        m=re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\d+) ts=(\d+)",ln)
        if m: cur={"type":m.group(1),"ts":int(m.group(3)),"body":[]};ev.append(cur);continue
        if cur is not None:
            if ln.startswith("###ADJ9_END"):cur=None;continue
            cur["body"].append(ln)
    return ev
def field(e,name):
    j="\n".join(e["body"])
    m=re.search(r"(?:^|\s)"+name+r"=([^\s]+)",j,re.M)
    return m.group(1) if m else None
pairs=[]  # (sec, [w0..w3])
for path in glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/*.log")+glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/device/*.log"):
    pin=None
    for e in parse_events(path):
        if e["type"]=="nsign_in": pin=e["ts"]
        elif e["type"]=="nsign":
            h=field(e,"hex")
            if h:
                w=struct.unpack(">4I",bytes.fromhex(h)[:16])
                pairs.append({"sec_in":(pin//1000) if pin else None,"sec_out":e["ts"]//1000,"w":w,"h":h[:32]})
                pin=None
# fiddler
b=base64.b64decode("QMgRTT9mxtofD3VyfhxE5s1jYqxb3XRxKZo988SMQaOuWQQfgYUsN1JK0QqRk7L5B6Te1pq+ltdKSmj8uG+6gaXboOKo5q+Lrm4pvjdw8w047bGpH2O4TfKLmKUgXv75iwrY3kxNTB7o93vEw9wC7YPpuD5ffEjIdbDsS5nonUQ4QQRXjhyXRVAEs8wlwwNaSqiKVLC/lRiEm5lfR88r2wMRsLKVZ5st267TQfQCKMY0unnK7uUl9r2QvMeNBNBQ")
pairs.append({"sec_in":1788856522,"sec_out":1788856522,"w":struct.unpack(">4I",b[:16]),"h":b[:16].hex(),"fiddler":True})
# dedupe by header
seen=set();P=[]
for p in pairs:
    if p["h"] in seen: continue
    seen.add(p["h"]); P.append(p)
print("unique (sec,header) pairs:",len(P))

A,C=0x5DEECE66D,0xB; M=1<<48
def streams(seed,n=200):
    # POSIX srand48: X0=(seed<<16)|0x330E
    X=((seed<<16)|0x330E)&(M-1)
    v31=[];v32=[]
    for _ in range(n):
        X=(X*A+C)%M
        v31.append(X>>17)                       # 31-bit (X>>17)
        v32.append((X>>16)&0xFFFFFFFF)          # 32-bit (seed[2]<<16)|(seed[1]>>16)
    return v31,v32

def try_model(P, seedof, gen):
    # gen(v31,v32,k) -> 4 words or None
    hits=0
    for p in P:
        ok=False
        for lbl in ("sec_in","sec_out"):
            s=p[lbl]
            if s is None: continue
            for d in (-2,-1,0,1,2):
                sd=s+d
                v31,v32=streams(sd)
                for k in range(0,60):
                    w=gen(v31,v32,k)
                    if w and tuple(w)==p["w"]:
                        hits+=1;ok=True
                        tag="FIDDLER" if p.get("fiddler") else p["h"][:16]
                        print("  HIT %-18s seed=%d(%s%+d) k=%d"%(tag,sd,lbl,d,k))
                        break
                if ok: break
            if ok: break
    return hits

models={
 "xor-disjoint-31": lambda v31,v32,k: [v31[k+2*i]^v31[k+2*i+1] for i in range(4)] if k+8<=len(v31) else None,
 "xor-disjoint-32": lambda v31,v32,k: [v32[k+2*i]^v32[k+2*i+1] for i in range(4)] if k+8<=len(v32) else None,
 "xor-overlap-31": lambda v31,v32,k: [v31[k+i]^v31[k+i+1] for i in range(4)],
 "xor-overlap-32": lambda v31,v32,k: [v32[k+i]^v32[k+i+1] for i in range(4)],
 "xor-stride2-31": lambda v31,v32,k: [v31[k+i]^v31[k+i+4] for i in range(4)],
 "raw-31": lambda v31,v32,k: [v31[k+i] for i in range(4)],
 "raw-32-masked": lambda v31,v32,k: [v32[k+i]&0x7FFFFFFF for i in range(4)],
 "raw-32": lambda v31,v32,k: [v32[k+i] for i in range(4)],
 "xor-alt-31 (0^1,1^2..)": lambda v31,v32,k: [v31[k+i]^v31[k+i+1] for i in range(4)],
 "sum31": lambda v31,v32,k: [(v31[k+2*i]+v31[k+2*i+1])&0x7FFFFFFF for i in range(4)],
}
for name,g in models.items():
    print("=== %s ==="%name)
    h=try_model(P[:8],None,g)
    print("   hits: %d/%d"%(h,min(8,len(P))))
