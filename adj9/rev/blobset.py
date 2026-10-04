# blobset.py — assemble (ts, blob192, canonical) dataset from all capture logs
import re,glob
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
def body_field(e,key):
    # find 'key=' then hex=.. ; bodies have lines like 'text: ...', 'hex=....', 'hex: ...'
    joined="\n".join(e["body"])
    m=re.search(key+r"=([0-9a-fA-F]+)",joined)
    return m.group(1) if m else None
def get_field(e,name):
    for b in e["body"]:
        if b.startswith(name+"=") or (" "+name+"=") in b or b.startswith("text:") and name+"=" in b:
            pass
    joined="\n".join(e["body"])
    m=re.search(r"(?:^|\s)"+name+r"=([^\s]+)",joined,re.M)
    return m.group(1) if m else None
blobs=[]
for path in glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/*.log"):
    ev=parse_events(path)
    for i,e in enumerate(ev):
        if e["type"]=="nsign":
            h=body_field(e,"hex")
            if h is None:
                # nsign body: 'text: len=192' then maybe hex line
                joined="\n".join(e["body"])
                m=re.search(r"^hex=([0-9a-f]+)",joined,re.M)
                h=m.group(1) if m else None
            blobs.append({"ts":e["ts"],"hex":h,"src":path.split("/")[-1],"idx":i})
print("nsign events total:",len(blobs))
ok=[b for b in blobs if b["hex"]]
print("with hex:",len(ok))
for b in ok[:3]:
    print(b["src"],b["ts"],b["hex"][:64],"len",len(b["hex"])//2)
import json
json.dump(ok,open("C:/Users/Apps/Downloads/com.penti.app/adj9/rev/blobset.json","w"))
