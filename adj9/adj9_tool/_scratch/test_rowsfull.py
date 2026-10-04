import sys, os, struct, json
HERE=os.path.dirname(os.path.abspath(__file__)); TOOL=os.path.dirname(HERE)
DEV=os.path.join(TOOL,'..','device')
sys.path.insert(0,TOOL)
import adj9_signer as A

def load(fn):
    d=json.load(open(os.path.join(DEV,fn),encoding="utf-8"))
    return d["rows"] if isinstance(d,dict) and "rows" in d else d

def capwords(r):
    desc=r.get("desc",r)
    out={}
    for k in ("0","2","4"):
        hexs=desc[k]["hex"] if isinstance(desc[k],dict) else desc[k]
        out[k]=[int.from_bytes(bytes.fromhex(hexs)[i:i+4],"big") for i in range(0,len(bytes.fromhex(hexs)),4)]
    return out

for fn in ("rows_full.json","rows_control.json"):
    rows=load(fn)
    print("=== %s : %d rows ===" % (fn, len(rows)))
    for idx,r in enumerate(rows):
        cw=capwords(r)
        cap2=cw["2"][0]
        seed=int.from_bytes(bytes.fromhex(desc2:=r["desc"]["2"]["hex"]),"little")
        want0=cw["0"]; want4=cw["4"]
        head = A.head_for_sign_id(r.get("sign_id",1)) if r.get("sign_id") else A.HEAD_FIRST
        d0,d2,d4 = A.region(seed,0,head=head)
        m0=sum(1 for a,b in zip(d0,want0) if a==b)
        m4=list(d4)==want4
        diff=[i for i in range(min(len(d0),len(want0))) if d0[i]!=want0[i]]
        print(" row %d sign_id=%s seed=%08x head=%s d0 match %d/%d diff=%s d4=%s" % (
            idx, r.get("sign_id"), seed, head, m0, len(want0), diff, m4))
    print()
