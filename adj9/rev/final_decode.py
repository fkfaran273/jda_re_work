import json, base64, struct
bs=json.load(open("blobset.json"))
sigs=json.load(open("saz_sigs.json"))
ps=json.load(open("pairset.json"))
h_by_ts={p["ts_in"]:bytes.fromhex(p["arg3"]) for p in ps}
print("=== 192B blobs decoded to dword streams (header 4 + body 44) ===")
allb=[]
for e in bs:
    raw=bytes.fromhex(e["hex"])
    dw=struct.unpack(">48I",raw)
    allb.append(("oracle",e["ts"],dw,raw))
for s in sigs:
    raw=base64.b64decode(s["sig_b64"])
    dw=struct.unpack(">48I",raw)
    allb.append(("saz%d"%s["sess"],None,dw,raw))
print("corpus:",len(allb),"blobs (34 oracle + 4 SAZ)")
# stable-vs-volatile across whole corpus: which dword positions are constant?
from collections import Counter
for pos in range(48):
    vals=set(dw[pos] for _,_,dw,_ in allb)
    if len(vals)==1:
        print("STABLE pos %d = %08x" % (pos,list(vals)[0]))
print("(no STABLE line above => 0/48 constant across devices/sessions, as expected)")
# same-second pair: which 4 dwords stable?
same=[x for x in bs if x["ts"]//1000==bs[0]["ts"]//1000]
import collections
by=collections.defaultdict(list)
for e in bs: by[e["ts"]//1000].append(e)
for sec,g in by.items():
    if len(g)>1:
        a=struct.unpack(">48I",bytes.fromhex(g[0]["hex"])); b=struct.unpack(">48I",bytes.fromhex(g[1]["hex"]))
        stable=[i for i in range(48) if a[i]==b[i]]
        print("same-second sec",sec,"stable dwords:",stable,["%08x"%a[i] for i in stable])
# H containment: is any pairset H (8 BE dwords) present raw/rev/LE in its own blob?
for p in ps[:6]:
    h=bytes.fromhex(p["arg3"]); blob=bytes.fromhex(p["blob"])
    hd=struct.unpack(">8I",h)
    bd=struct.unpack(">48I",blob)
    hit_be=any(all(bd[i+k]==hd[k] for k in range(8)) for i in range(41))
    rev=struct.unpack("<8I",h)
    hit_le=any(all(bd[i+k]==rev[k] for k in range(8)) for i in range(41))
    print("H-contain ts=%d rawBE=%s rawLE=%s (both expect False: H is whitened, not stored)" % (p["ts_in"],hit_be,hit_le))
