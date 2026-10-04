import json, struct
bs=json.load(open("blobset.json"))
from collections import defaultdict
by=defaultdict(list)
for e in bs:
    by[e["ts"]//1000].append(e)
ss=[v for v in by.values() if len(v)>1]
print("same-second groups:",len(ss))
for g in ss[:5]:
    a=bytes.fromhex(g[0]["hex"]); b=bytes.fromhex(g[1]["hex"])
    nd=sum(1 for x,y in zip(a,b) if x!=y)
    hd=sum(1 for x,y in zip(a[:16],b[:16]) if x!=y)
    da=struct.unpack(">48I",a); db=struct.unpack(">48I",b)
    print("n=%d dt_ms=%d header_diff=%d/16 byte_diff=%d/192 dword_diff=%d/48" % (len(g),abs(g[0]["ts"]-g[1]["ts"]),hd,nd,sum(1 for x,y in zip(da,db) if x!=y)))
    print(" hdrA",a[:16].hex(),"hdrB",b[:16].hex())
