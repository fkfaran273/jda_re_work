# xor_pair_test.py — header words = XOR of consecutive lrand48 draws?
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
recs=[]
for path in glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/*.log")+glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/device/*.log"):
    pin=None
    for e in parse_events(path):
        if e["type"]=="nsign_in": pin=e["ts"]
        elif e["type"]=="nsign":
            h=field(e,"hex")
            if h: recs.append({"tin":pin,"tout":e["ts"],"hex":h}); pin=None
seen=set();u=[]
for r in recs:
    if r["hex"] in seen: continue
    seen.add(r["hex"]); u.append(r)
u.append({"tin":1788856522928,"tout":1788856522942,"hex":base64.b64decode("QMgRTT9mxtofD3VyfhxE5s1jYqxb3XRxKZo988SMQaOuWQQfgYUsN1JK0QqRk7L5B6Te1pq+ltdKSmj8uG+6gaXboOKo5q+Lrm4pvjdw8w047bGpH2O4TfKLmKUgXv75iwrY3kxNTB7o93vEw9wC7YPpuD5ffEjIdbDsS5nonUQ4QQRXjhyXRVAEs8wlwwNaSqiKVLC/lRiEm5lfR88r2wMRsLKVZ5st267TQfQCKMY0unnK7uUl9r2QvMeNBNBQ").hex(),"fiddler":True})
print("corpus:",len(u))
A,C,M=0x5DEECE66D,0xB,1<<48
def lrand_stream(seed,n):
    s=((seed&0xFFFFFFFF)<<16)|0x330E
    s&=M-1
    out=[]
    for _ in range(n):
        s=(s*A+C)%M
        out.append(s>>17)
    return out
hits=0
for r in u:
    w=struct.unpack(">4I",bytes.fromhex(r["hex"])[:16])
    seeds={}
    for lbl,t in (("tin",r["tin"]),("tout",r["tout"])):
        if t is None: continue
        for d in (-2,-1,0,1,2):
            seeds["%s%+d"%(lbl,d)]=t//1000+d
    found=[]
    for lbl,sd in seeds.items():
        st=lrand_stream(sd,100)
        # model A: disjoint pairs  w0=s[k]^s[k+1], w1=s[k+2]^s[k+3]...
        for k in range(92):
            cand=(st[k]^st[k+1],st[k+2]^st[k+3],st[k+4]^st[k+5],st[k+6]^st[k+7])
            if cand==w: found.append(("disjoint",lbl,sd,k))
        # model B: overlapping w_i = s[k+i]^s[k+i+1]
        for k in range(95):
            cand=tuple(st[k+i]^st[k+i+1] for i in range(4))
            if cand==w: found.append(("overlap",lbl,sd,k))
        # model C: pairs strided by 2 with offset: w_i = s[k+2i]^s[k+2i+1] (same as A)
        # model D: sums
        for k in range(95):
            cand=tuple(((st[k+i]+st[k+i+1])&0x7FFFFFFF) for i in range(4))
            if cand==w: found.append(("sum",lbl,sd,k))
    if found:
        hits+=1
        tag="FIDDLER" if r.get("fiddler") else "moto"
        print("HIT [%s] blob=%s :: %s"%(tag,r["hex"][:16],found[:4]))
print("XOR-pair model hits: %d/%d"%(hits,len(u)))
