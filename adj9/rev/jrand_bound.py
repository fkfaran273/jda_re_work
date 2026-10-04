# jrand_bound.py — Java Random.nextInt(bound=0x7fffffff) model for the 16-byte header
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
for path in glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/*.log"):
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
# add Fiddler ground truth (OnePlus): created_at epoch sec, header words
u.append({"tin":1788856522928,"tout":1788856522942,"hex":base64.b64decode("QMgRTT9mxtofD3VyfhxE5s1jYqxb3XRxKZo988SMQaOuWQQfgYUsN1JK0QqRk7L5B6Te1pq+ltdKSmj8uG+6gaXboOKo5q+Lrm4pvjdw8w047bGpH2O4TfKLmKUgXv75iwrY3kxNTB7o93vEw9wC7YPpuD5ffEjIdbDsS5nonUQ4QQRXjhyXRVAEs8wlwwNaSqiKVLC/lRiEm5lfR88r2wMRsLKVZ5st267TQfQCKMY0unnK7uUl9r2QvMeNBNBQ").hex(),"fiddler":True})
print("corpus:",len(u))
M48=(1<<48)-1
A,C=0x5DEECE66D,0xB
def jseq(seed,draws,bound=None):
    s=(seed ^ A) & M48   # Java setSeed/ctor scramble
    out=[]
    for _ in range(draws):
        s=(s*A+C)&M48
        if bound is None:
            out.append((s>>16)&0xFFFFFFFF)          # nextInt() 32-bit
        else:
            x=s>>17                                   # next(31)
            if bound==(1<<31)-1:
                # bound not power of two: while(x - x%b + b overflows) retry; x%b
                # for b=2^31-1, x-(x%b)+b overflow means x%b + b > 2^31... compute directly
                while (x - (x % bound) + bound) > 0x7FFFFFFF*2-1 or (x - (x%bound) + bound) >= (1<<32) or False:
                    # fallback: rare retry; emulate overflow condition: retry if x-(x%b)+b >= 2^31
                    if (x - (x % bound) + bound) < (1<<31): break
                    s=(s*A+C)&M48; x=s>>17
                out.append(x % bound)
    return out
hits=0
for r in u:
    w=struct.unpack(">4I",bytes.fromhex(r["hex"])[:16])
    assert all(x<(1<<31) for x in w)
    bases=[("tin",r["tin"]),("tout",r["tout"])]
    seeds={}
    for lbl,t in bases:
        if t is None: continue
        for d in (-1,0,1):
            seeds["%s%+d"%(lbl,d)]=(t//1000)+d
    found=[]
    for lbl,sd in seeds.items():
        for skip in range(0,25):
            for bound,lbl2 in [(0x7fffffff,"nextInt(2^31-1)"),(None,"nextInt()"),((1<<30),"nextInt(2^30)")]:
                seq=jseq(sd,skip+4+8,bound)
                for k in range(skip,skip+8):
                    if tuple(seq[k:k+4])==w:
                        found.append((lbl,sd,k,bound))
    if found:
        hits+=1
        print("HIT %s blob=%s :: %s"%(r.get("fiddler") and "FIDDLER" or "moto",r["hex"][:16],found[:3]))
print("Java-Random-bound model: %d/%d"%(hits,len(u)))
