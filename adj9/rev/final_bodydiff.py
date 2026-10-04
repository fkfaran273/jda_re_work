import json, struct
ps=json.load(open("pairset.json"))
print("pairs:",len(ps))
# find same-input same-second pair (A1~A2 analogue): same arg3, ts within 1s
for i,p in enumerate(ps[:12]):
    raw=bytes.fromhex(p["blob"])
    print(i, p["ts_in"], p["arg3"][:16], len(raw), raw[:16].hex())
# differential: first two with same arg3?
from collections import defaultdict
by=defaultdict(list)
for p in ps:
    by[p["arg3"]].append(p)
rep=[v for v in by.values() if len(v)>1]
print("repeat-arg3 groups:",len(rep))
for g in rep[:3]:
    a=bytes.fromhex(g[0]["blob"]); b=bytes.fromhex(g[1]["blob"])
    nd=sum(1 for x,y in zip(a,b) if x!=y)
    hd=sum(1 for x,y in zip(a[:16],b[:16]) if x!=y)
    print("same-H pair ndiff=%d/192 header_diff=%d/16 dt_ms=%d" % (nd,hd,abs(g[0]["ts_in"]-g[1]["ts_in"])))
    # dword diff
    da=struct.unpack(">48I",a); db=struct.unpack(">48I",b)
    print(" dword diff:",sum(1 for x,y in zip(da,db) if x!=y),"/48")
# descriptor inventory from slice6 (static, re-assert lengths)
print("desc lens (dw): 36,0,1,?,8,1,1,1,4,5,?  total>=56dw in, 48dw out (16+176)")
