# type3_xor.py — bionic rand()=random() TYPE_3; header words = XOR of consecutive pairs
import re,glob,struct,base64
def parse_events(path):
    lines=open(path,encoding="utf-8",errors="replace").read().splitlines()
    ev=[];cur=None
    for ln in lines:
        m=re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\d+) ts=(\d+)",ln)
        if m: cur={"type":m.group(1),"ts":int(m.group(3)),"body":[]};ev.append(cur);continue
        if cur is not None:
            if ln.startswith("###ADJ9_END"):cur=None;continue
            cur["body"].append(ln)
    return ev
def field(e,name):
    j="\n".join(e["body"])
    m=re.search(r"(?:^|\s)"+name+r"=([^\s]+)",j,re.M)
    return m.group(1) if m else None
pairs=[]
for path in glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/*.log")+glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/device/*.log"):
    pin=None
    for e in parse_events(path):
        if e["type"]=="nsign_in": pin=e["ts"]
        elif e["type"]=="nsign":
            h=field(e,"hex")
            if h:
                w=struct.unpack(">4I",bytes.fromhex(h)[:16])
                pairs.append({"sec_in":(pin//1000) if pin else None,"sec_out":e["ts"]//1000,"w":w,"h":h[:32]})
                pin=None
b=base64.b64decode("QMgRTT9mxtofD3VyfhxE5s1jYqxb3XRxKZo988SMQaOuWQQfgYUsN1JK0QqRk7L5B6Te1pq+ltdKSmj8uG+6gaXboOKo5q+Lrm4pvjdw8w047bGpH2O4TfKLmKUgXv75iwrY3kxNTB7o93vEw9wC7YPpuD5ffEjIdbDsS5nonUQ4QQRXjhyXRVAEs8wlwwNaSqiKVLC/lRiEm5lfR88r2wMRsLKVZ5st267TQfQCKMY0unnK7uUl9r2QvMeNBNBQ")
pairs.append({"sec_in":1788856522,"sec_out":1788856522,"w":struct.unpack(">4I",b[:16]),"h":b[:16].hex(),"fiddler":True})
seen=set();P=[]
for p in pairs:
    if p["h"] in seen: continue
    seen.add(p["h"]); P.append(p)
print("pairs:",len(P))
M31=2147483647
class Random3:
    __slots__=("r","f","b")
    def __init__(self, seed):
        r=self.r=[0]*31
        s=seed & 0xFFFFFFFF
        if s==0: s=1
        # bionic: srandom(unsigned int) -> param long: value 0..2^32-1, stored in int32 state[0]
        w = s if s < 2**31 else s - 2**32
        r[0]=w
        prev=w
        for i in range(1,31):
            # Schrage on possibly-negative prev (C: long arithmetic; seed>=2^31 gives negative prev first step)
            if prev>=0:
                hi=prev//127773; lo=prev-hi*127773
            else:
                # C truncation toward zero
                hi=-((-prev)//127773); lo=prev-hi*127773
            word=16807*lo-2836*hi
            if word<0: word+=M31
            prev=word; r[i]=word
        self.f=3; self.b=0
        for _ in range(310): self.next()
    def next(self):
        v=(self.r[self.f]+self.r[self.b])&0xFFFFFFFF
        self.r[self.f]=v if v<2**31 else v-2**32
        out=v>>1
        self.f=(self.f+1)%31
        self.b=(self.b+1)%31
        return out
hits=0;found={}
for p in P:
    ok=False
    for lbl in ("sec_in","sec_out"):
        if p[lbl] is None: continue
        for d in (-1,0,1):
            sd=p[lbl]+d
            R=Random3(sd)
            # pre-draw 400 to have full window
            seq=[R.next() for _ in range(400)]
            for k in range(0,320):
                for nm,w in (
                  ("xorD",[seq[k+2*i]^seq[k+2*i+1] for i in range(4)]),
                  ("raw",[seq[k+i] for i in range(4)]),
                ):
                    if tuple(w)==p["w"]:
                        tag="FIDDLER" if p.get("fiddler") else p["h"][:16]
                        print("HIT %-18s seed=%d(%s%+d) skip=%d model=%s"%(tag,sd,lbl,d,k,nm))
                        hits+=1;ok=True;found[nm]=found.get(nm,0)+1
                        break
                if ok:break
            if ok:break
        if ok:break
print("TYPE_3 XOR-pair hits: %d/%d %s"%(hits,len(P),found))
