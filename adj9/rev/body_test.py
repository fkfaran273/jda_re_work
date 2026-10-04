# body_test.py — is the 176B body also rand()-XOR-pairs (draws 8+)?
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
            if h: pairs.append({"tin":pin,"tout":e["ts"],"raw":bytes.fromhex(h)}); pin=None
pairs.append({"tin":1788856522928,"tout":1788856522942,"raw":base64.b64decode("QMgRTT9mxtofD3VyfhxE5s1jYqxb3XRxKZo988SMQaOuWQQfgYUsN1JK0QqRk7L5B6Te1pq+ltdKSmj8uG+6gaXboOKo5q+Lrm4pvjdw8w047bGpH2O4TfKLmKUgXv75iwrY3kxNTB7o93vEw9wC7YPpuD5ffEjIdbDsS5nonUQ4QQRXjhyXRVAEs8wlwwNaSqiKVLC/lRiEm5lfR88r2wMRsLKVZ5st267TQfQCKMY0unnK7uUl9r2QvMeNBNBQ"),"fiddler":True})
seen=set();P=[]
for p in pairs:
    if p["raw"][:16].hex() in seen: continue
    seen.add(p["raw"][:16].hex()); P.append(p)
print("corpus:",len(P))
M31=2147483647
class Random3:
    __slots__=("r","f","b")
    def __init__(self, seed):
        r=self.r=[0]*31
        s=seed & 0xFFFFFFFF
        if s==0: s=1
        w = s if s < 2**31 else s - 2**32
        r[0]=w; prev=w
        for i in range(1,31):
            if prev>=0: hi=prev//127773; lo=prev-hi*127773
            else: hi=-((-prev)//127773); lo=prev-hi*127773
            word=16807*lo-2836*hi
            if word<0: word+=M31
            prev=word; r[i]=word
        self.f=3; self.b=0
        for _ in range(310): self.next()
    def next(self):
        v=(self.r[self.f]+self.r[self.b])&0xFFFFFFFF
        self.r[self.f]=v if v<2**31 else v-2**32
        out=v>>1
        self.f=(self.f+1)%31; self.b=(self.b+1)%31
        return out
# For each blob find its seed (test sec_in/sec_out ±1 by matching header), then check body
full_body_match=0; body_tested=0
for p in P:
    raw=p["raw"]
    seed=None
    for lbl in ("tin","tout"):
        if p[lbl] is None: continue
        for d in (0,1):
            sd=(p[lbl]//1000)+d
            R=Random3(sd); seq=[R.next() for _ in range(200)]
            hdr=tuple(seq[2*i]^seq[2*i+1] for i in range(4))
            if struct.unpack(">4I",raw[:16])==hdr: seed=sd; break
        if seed: break
    if seed is None: continue
    body_tested+=1
    # hypothesis: body words continue as XOR pairs draws 8..179 -> 44 words? only 86 draws needed for 43 words... 176B=44 words -> draws 8..95
    R=Random3(seed); seq=[R.next() for _ in range(120)]
    xs=[seq[8+2*i]^seq[8+2*i+1] for i in range(44)]
    expect=b"".join(struct.pack(">I",x) for x in xs)
    if expect==raw[16:]:
        full_body_match+=1
        print("FULL-BODY PRNG MATCH seed=%d blob=%s"%(seed,raw[:16].hex()))
    else:
        # how many leading body words match?
        n=0
        for i in range(44):
            if struct.unpack(">I",raw[16+4*i:20+4*i])[0]==xs[i]: n+=1
            else: break
        print("seed=%d blob=%s body PRNG-words matching from draw8: %d/44"%(seed,raw[:8].hex(),n))
print("full-body matches: %d/%d tested"%(full_body_match,body_tested))
