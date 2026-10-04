# chain_test.py — test whether consecutive nSign headers form a PRNG chain
import re,glob,json,struct,itertools
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
# per-log ordered nsign sequences
seqs={}
for path in glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/oracle_run*.log"):
    ev=parse_events(path)
    seq=[]
    for e in ev:
        if e["type"]=="nsign":
            h=field(e,"hex")
            if h: seq.append((e["ts"],h))
    if len(seq)>=2:
        seqs[path.split("\\")[-1] if "\\" in path else path.split("/")[-1]]=seq
for k,v in sorted(seqs.items()): print(k,"calls:",len(v))
# gather all consecutive pairs across logs (also pairset for cross-check)
def words(ts,h):
    b=bytes.fromhex(h)[:16]
    return struct.unpack(">4I",b), b
print("\n=== A. LCG chain test on consecutive headers (glibc constants) ===")
A,C,M=1103515245,12345,1<<31
hits=0;tot=0
for k,seq in sorted(seqs.items()):
    for (t0,h0),(t1,h1) in zip(seq,seq[1:]):
        w0,_=words(t0,h0); w1,_=words(t1,h1)
        for i in range(4):
            tot+=1
            if (A*w0[i]+C)%M==w1[i]:
                hits+=1; print("  HIT",k,hex(t0),hex(t1),"w",i)
print("glibc LCG: %d/%d"%(hits,tot))
# also test reverse: w0 = A*w1+C
hits=0
for k,seq in sorted(seqs.items()):
    for (t0,h0),(t1,h1) in zip(seq,seq[1:]):
        w0,_=words(t0,h0); w1,_=words(t1,h1)
        for i in range(4):
            if (A*w1[i]+C)%M==w0[i]: hits+=1; print("  REVHIT",k,i)
print("reverse:",hits)
print("\n=== B. header words vs timestamps ===")
for k,seq in sorted(seqs.items()):
    for ts,h in seq[:4]:
        w,_=words(ts,h)
        sec=ts//1000; ms=ts%1000
        print(" ts=%d w=[%08x %08x %08x %08x] sec=%x ms=%x"%(ts,w[0],w[1],w[2],w[3],sec,ms))
print("\n=== C. header equals across calls? full-dup check ===")
allh=[]
for k,seq in sorted(seqs.items()):
    for ts,h in seq: allh.append((k,ts,h))
from collections import Counter
c=Counter(h[:32] for _,_,h in allh)
for hd,n in c.items():
    if n>1: print("header",hd,"appears",n,"times")
