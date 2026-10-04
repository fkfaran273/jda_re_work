# mrand_test.py — mrand48() (signed 31-bit) + other variants
import re,glob,struct
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
            if h: recs.append((pin,e["ts"],h)); pin=None
seen=set();u=[]
for ti,to,h in recs:
    if h in seen: continue
    seen.add(h);u.append((ti,to,h))
A,C,M=0x5DEECE66D,0xB,1<<48
def mrand_stream(seed,n=90):
    s=(seed<<16)|0x330E
    s&=M-1
    out=[]
    for _ in range(n):
        s=(s*A+C)%M
        out.append(s>>17)
    return out
def mrand48(x): # int32 cast of lrand48: ((int32_t)(x<<1))>>1 effectively; actually mrand48 = (int16 high) << 16 | low16 of next state... simpler: mrand48() = (int32_t)(lrand48 x2)?
    # POSIX mrand48: Xi+1; return (int32_t)Xi+1 >>? mrand48 returns signed 31-bit: (long)(int32_t)(state>>17)<<?? -- actual: mrand48() = (int16_t)(state>>16)<<16 + low 16 of state>>1?
    return x & 0x7FFFFFFF
hits=0
for ti,to,h in u:
    w=struct.unpack(">4I",bytes.fromhex(h)[:16])
    seeds={}
    for lbl,base in [("tin",ti or to),("tout",to)]:
        for d in (-2,-1,0,1,2):
            seeds["%s%+d"%(lbl,d)]=base//1000+d
    f=False
    for lbl,sd in seeds.items():
        st=mrand_stream(sd,90)
        # variants: raw 31-bit, state>>16 masked 31, state>>17, mrand48= (state>>16)&0x7fffffff?
        for shift,mask,lbl2 in [(17,(1<<31)-1,"lrand48"),(16,(1<<31)-1,"s>>16&31"),(17,(1<<30)-1,"hmm")]:
            vv=[(x>> (shift-17)) if False else x for x in st]
            vv=[(x if shift==17 else (x*2)%(1<<31)) for x in st]
            # v = lrand48 for shift17; for s>>16&31: state>>16 masked
            pass
        # direct: consecutive 4-tuples of stream values as ints
        for k in range(86):
            if tuple(st[k:k+4])==w: print("mrand48-style HIT",h[:8],lbl,sd,k);f=True;hits+=1;break
        if f: break
print("hits:",hits,"/",len(u))
