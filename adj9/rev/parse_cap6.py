# parse_cap6.py — reconstruct event sequence from adj9_capture6.log
import re,sys
LOG="C:/Users/Apps/Downloads/com.penti.app/adj9/cap/adj9_capture6.log"
lines=open(LOG,encoding="utf-8",errors="replace").read().splitlines()
events=[]  # (ts, type, fields, body)
cur=None
for ln in lines:
    m=re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\d+) ts=(\d+)",ln)
    if m:
        cur={"type":m.group(1),"ts":int(m.group(3)),"body":[]}
        events.append(cur); continue
    if cur is not None:
        if ln.startswith("###ADJ9_END"):
            cur=None; continue
        cur["body"].append(ln)
print("events:",len(events))
# find nsign events
for i,e in enumerate(events):
    if e["type"] in ("nsign","nsign_in"):
        print(i,e["type"],e["ts"])
# timeline around first nsign
idx=[i for i,e in enumerate(events) if e["type"]=="nsign"][0]
print("\n=== window around first nsign (idx %d) ==="%idx)
lo=max(0,idx-40)
for j in range(lo,min(len(events),idx+40)):
    e=events[j]
    b0=e["body"][0] if e["body"] else ""
    print("%5d ts=%d %-24s %s"%(j,e["ts"],e["type"],b0[:100]))
