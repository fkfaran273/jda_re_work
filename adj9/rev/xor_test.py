# xor_test.py — decisive tests on blob corpus
import json, hashlib, struct, itertools, binascii
blobs=json.load(open("C:/Users/Apps/Downloads/com.penti.app/adj9/rev/blobset.json"))
def B(b): return bytes.fromhex(b["hex"])
for b in blobs: b["raw"]=B(b)
# dedupe by (ts,hex)
seen=set(); uniq=[]
for b in blobs:
    k=(b["ts"],b["hex"])
    if k in seen: continue
    seen.add(k); uniq.append(b)
print("unique (ts,hex):",len(uniq))
# 1) same-second pairs: XOR of full 192B
print("\n=== same-second pairs: XOR diff ===")
pairs=0
for a,c in itertools.combinations(uniq,2):
    if a["ts"]//1000==c["ts"]//1000:
        x=bytes(p^q for p,q in zip(a["raw"],c["raw"]))
        nz=[i for i,v in enumerate(x) if v]
        print("ts %d/%d (dt=%dms) diff-bytes=%d"%(a["ts"],c["ts"],abs(a["ts"]-c["ts"]),len(nz)))
        if len(nz)<=40: print("   diff positions:",nz[:40])
        pairs+=1
print("same-second pairs:",pairs)
