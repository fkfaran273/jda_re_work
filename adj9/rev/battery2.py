# battery2.py — corrected PRNG battery: within-header + cross-header-with-gap tests
import re,glob,struct,itertools
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
# collect ALL blobs (ts) from every log
blobs=[]
for path in glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/*.log"):
    ev=parse_events(path)
    prev_in=None
    for e in ev:
        if e["type"]=="nsign_in": prev_in=e["ts"]
        elif e["type"]=="nsign":
            h=field(e,"hex")
            if h: blobs.append((prev_in,e["ts"],h)); prev_in=None
# dedupe
seen=set();uniq=[]
for ti,to,h in blobs:
    if h in seen: continue
    seen.add(h); uniq.append((ti,to,h))
print("unique blobs:",len(uniq))
def words(h): return list(struct.unpack(">4I",bytes.fromhex(h)[:16]))
M31=(1<<31)-1
# ---------- 1. WITHIN-HEADER chain tests ----------
print("\n=== within-header: glibc TYPE_0 (x*1103515245+12345 mod 2^31) ===")
A,C=1103515245,12345
hits=0;tot=0
for ti,to,h in uniq:
    w=words(h)
    for i in range(3):
        tot+=1
        if (A*w[i]+C)% (1<<31) == w[i+1]: hits+=1; print("  HIT",h[:8],i)
print(" %d/%d"%(hits,tot))
# glibc TYPE_0 output = state (which already mod 2^31 by masking &0x7fffffff)
print("\n=== within-header: Java Random nextInt ===")
JA,JC=0x5DEECE66D,0xB
hits=0;tot=0
for ti,to,h in uniq:
    w=words(h)
    for i in range(3):
        for lo in range(65536):
            s=(w[i]<<16)|lo
            s2=(s*JA+JC)&((1<<48)-1)
            if (s2>>16)==w[i+1]:
                hits+=1;tot+=1;print("  HIT",h[:8],i,"lo=%04x"%lo);break
        else: tot+=1
print(" %d/%d"%(hits,tot))
print("\n=== within-header: lrand48 (state*25214903917+11 mod 2^48, out=state>>17) ===")
LA,LC=0x5DEECE66D,0xB
hits=0;tot=0
for ti,to,h in uniq:
    w=words(h)
    for i in range(3):
        found=False
        for lo in range(1<<17):
            s=((w[i]<<17)|lo)&((1<<48)-1)
            s2=(s*LA+LC)&((1<<48)-1)
            if (s2>>17)==w[i+1]:
                hits+=1;found=True;break
        tot+=1
        if found: print("  HIT",h[:8],i,"lo17=%05x"%lo)
print(" %d/%d"%(hits,tot))
