# pairset.py — build (ts_in, arg3, ts_out, blob192, canonical) tuples from all logs
import re,glob,json
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
    ev=parse_events(path)
    pending=None
    for e in ev:
        if e["type"]=="nsign_in":
            pending={"ts_in":e["ts"],"arg3":field(e,"arg3_hex"),"arg4":field(e,"arg4_int")}
        elif e["type"]=="nsign" and pending:
            h=field(e,"hex")
            if h: pending["blob"]=h; pending["ts_out"]=e["ts"]; pending["src"]=path
            else: pending=None
        elif e["type"]=="sign_input" and pending and "blob" in pending:
            # canonical = the hex: line (decoded utf8 of map)
            j="\n".join(e["body"])
            m=re.search(r"^hex: ([0-9a-f]+)",j,re.M)
            if m: pending["canonical_hex"]=m.group(1)
            m2=re.search(r"map_size=(\d+)",j)
            if m2: pending["map_size"]=m2.group(1)
            recs.append(pending); pending=None
print("paired records:",len(recs))
for r in recs[:3]:
    print(r["ts_in"],r["arg3"][:16],"blob",r["blob"][:16],"canon_len",len(r.get("canonical_hex",""))//2)
json.dump(recs,open("C:/Users/Apps/Downloads/com.penti.app/adj9/rev/pairset.json","w"))
