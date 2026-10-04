# BSD/glibc/bionic TYPE_3 additive-feedback random() — the model we never tested.
# bionic: srand(x)==srandom(x), rand()==random(). TYPE_3: deg=31, sep=3.
# init: r[0]=seed; r[i]=(16807*r[i-1])%2147483647 (signed Schrage, +M if <=0)
#       r[31..33]=r[0..2]; discard 310 outputs; out=(uint32)(r[f]+=r[r])>>1
import re, glob, struct
from collections import defaultdict

rows=[]
for lf in glob.glob("../cap/*.log"):
    data=open(lf,"rb").read().decode("utf-8","ignore")
    for m in re.finditer(r"--- (\d+) t0=(\d+) t1=(\d+) ms=\d+ sec=(\d+) len=192\n([0-9a-f]{384})", data):
        rows.append((int(m.group(4)), int(m.group(2)), int(m.group(3)), bytes.fromhex(m.group(5))))
seen={}
for sec,t0,t1,b in rows: seen.setdefault(sec,(t0,t1,b[:16]))
items=list(seen.items())
print("unique-second headers:",len(items))

M31=2147483647
class Random:
    def __init__(self, seed):
        self.r=[0]*34
        s=seed & 0xffffffff
        if s==0: s=1
        # seed may be interpreted as long (32-bit uint on 64-bit bionic)
        w=s if s < 2**31 else s  # keep as-is; Schrage below handles positive only
        # bionic passes unsigned int to srandom(long) -> value is 0..2^32-1.
        # OpenBSD: if seed==0 seed=1. state[0]=seed (as long). For seed>=2^31,
        # the Schrage loop below with negative word gives different results.
        self.r[0]=w if w < 2**31 else w - 2**32  # sign-extend to long
        for i in range(1,31):
            word=self.r[i-1]
            hi=int(word/127773); lo=word-hi*127773  # C truncation
            word=16807*lo-2836*hi
            if word<=0: word+=M31
            self.r[i]=word
        for i in range(31,34): self.r[i]=self.r[i-31]
        self.f=3; self.b=0  # fptr=&state[3], rptr=&state[0] (cyclic on 31)
        for _ in range(310): self.next()
    def next(self):
        i=self.f; j=self.b
        v=(self.r[i]+self.r[j])&0xffffffff
        self.r[i]=v
        # store as signed long like C
        self.r[i]=v if v<2**31 else v-2**32
        out=(v>>1)
        self.f=(self.f+1)%31
        self.b=(self.b+1)%31
        return out

def draws(seed,n,skip=0):
    R=Random(seed)
    for _ in range(skip): R.next()
    return [R.next() for _ in range(n)]

def pack_be(vs): return b"".join(struct.pack(">I",v) for v in vs)
def pack_le(vs): return b"".join(struct.pack("<I",v) for v in vs)

best=[]
for seedname,seedfn in (("sec",lambda s,t0,t1:s),
                        ("sec+1",lambda s,t0,t1:s+1),
                        ("t0ms",lambda s,t0,t1:t0//1000),
                        ("t1ms",lambda s,t0,t1:t1//1000)):
    for skip in range(0,40):
        for pk,pn in ((pack_be,"BE"),(pack_le,"LE")):
            ok=0
            for sec,(t0,t1,p) in items:
                vs=draws(seedfn(sec,t0,t1),4,skip)
                if pk(vs)==p: ok+=1
            if ok: print("HIT seed=%s skip=%d %s: %d/%d"%(seedname,skip,pn,ok,len(items)))

# pairwise: maybe only 2 draws per signing (2 call sites), 2nd call re-seeded same sec
for seedname,seedfn in (("sec",lambda s,t0,t1:s),):
    for skip in range(0,40):
        ok=0
        for sec,(t0,t1,p) in items:
            s=seedfn(sec,t0,t1)
            a=draws(s,2,skip)
            b2=draws(s,2,skip)
            if pack_be(a+a)==p: ok+=1
        if ok: print("HIT(2+2) seed=%s skip=%d: %d"%(seedname,skip,ok))

# sanity: distribution check — first draws for seed=sec for two different secs
for sec,(t0,t1,p) in items[:5]:
    print(sec, p.hex(), "->", [d for d in draws(sec,4)[:4]])
