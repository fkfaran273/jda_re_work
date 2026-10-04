# sec_law.py — verify: header determined by wall-clock second?
import re,glob,struct
from collections import defaultdict
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
    for e in parse_events(path):
        if e["type"]=="nsign":
            h=field(e,"hex")
            if h: recs.append((e["ts"],h))
print("total nsign-with-hex:",len(recs))
bysec=defaultdict(set)
for ts,h in recs: bysec[ts//1000].add(h[:32])
same=0;diff=0
for sec,hs in sorted(bysec.items()):
    if len(hs)>1:
        print("sec %d: %d distinct headers"%(sec,len(hs)))
        diff+=1
    else:
        n=sum(1 for ts,h in recs if ts//1000==sec)
        if n>1: same+=1; print("sec %d: %d calls share header %s"%(sec,n,list(hs)[0]))
print("\nseconds with >1 call sharing header:",same,"  seconds with differing headers:",diff)
# also: distinct seconds → distinct headers?
allh=defaultdict(set)
for ts,h in recs: allh[h[:32]].add(ts//1000)
multi=[(h,secs) for h,secs in allh.items() if len(secs)>1]
print("headers seen in multiple seconds:",multi if multi else "NONE")
