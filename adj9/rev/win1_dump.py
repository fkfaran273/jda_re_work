import re
LOG="C:/Users/Apps/Downloads/com.penti.app/adj9/cap/adj9_capture6.log"
lines=open(LOG,encoding="utf-8",errors="replace").read().splitlines()
events=[]; cur=None
for ln in lines:
    m=re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\d+) ts=(\d+)",ln)
    if m:
        cur={"type":m.group(1),"ts":int(m.group(3)),"body":[]}
        events.append(cur); continue
    if cur is not None:
        if ln.startswith("###ADJ9_END"): cur=None; continue
        cur["body"].append(ln)
# first window: events 1106..1206
for j in range(1106,1207):
    e=events[j]
    print("--- %d ts=%d %s"%(j,e["ts"],e["type"]))
    for b in e["body"]:
        print("   ",b[:180])
