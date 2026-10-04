import re, glob, struct, hashlib, hmac
from collections import defaultdict

# ---- load rows
rows=[]
for lf in glob.glob("cap/*.log"):
    data=open(lf,"rb").read().decode("utf-8","ignore")
    for m in re.finditer(r"--- (\d+) t0=(\d+) t1=(\d+) ms=\d+ sec=(\d+) len=192\n([0-9a-f]{384})", data):
        rows.append((int(m.group(4)), int(m.group(2)), bytes.fromhex(m.group(5))))
seen={}
for sec,t0,b in rows: seen.setdefault(sec,b[:16])
items=list(seen.items())
print("secs:",len(items))

def pack_be(vals): return b"".join(struct.pack(">I",v&0xffffffff) for v in vals)
def pack_le(vals): return b"".join(struct.pack("<I",v&0xffffffff) for v in vals)

# ---- model: masked hash words
def try_model(fn,name):
    hit=0
    for sec,prefix in items:
        v=fn(sec)
        if v==prefix: hit+=1
    if hit: print("HIT",name,hit)
    return hit

models={}
def add(name,f): models[name]=f

for hname,hf in (("sha1",hashlib.sha1),("sha256",hashlib.sha256),("md5",hashlib.md5)):
    for sname,ser in (("be32",lambda s:struct.pack(">I",s)),("ascii",lambda s:str(s).encode())):
        def mk(hf=hf,ser=ser):
            def f(s):
                d=hf(ser(s)).digest()
                words=struct.unpack(">4I",d[:16])
                return pack_be(w&0x7fffffff for w in words)
            return f
        add("mask_%s_%s"%(hname,sname),mk())
        def mk2(hf=hf,ser=ser):
            def f(s):
                d=hf(ser(s)).digest()
                words=struct.unpack(">4I",d[:16])
                return pack_be(words)
            return f
        add("raw_%s_%s"%(hname,sname),mk2())

# HMAC with captured keys
K1=bytes.fromhex("f065595e09288254f06195ac44cb3e1917c217bca57fea117de05149475ac05b")
K2=bytes.fromhex("3cd000451739baaac19dcc1f3f686d0dc302cacdd32be061eb842100c4f28f48")
for kn,K in (("K1",K1),("K2",K2)):
    for sname,ser in (("be32",lambda s:struct.pack(">I",s)),("ascii",lambda s:str(s).encode())):
        def mk(K=K,ser=ser,mask=True):
            def f(s):
                d=hmac.new(K,ser(s),hashlib.sha256).digest()
                words=struct.unpack(">4I",d[:16])
                if mask: words=[w&0x7fffffff for w in words]
                return pack_be(words)
            return f
        add("hmac%s_%s_mask"%(kn,sname),mk())
        add("hmac%s_%s_raw"%(kn,sname),mk(mask=False))

# AES-ECB(K, secblock)
from Crypto.Cipher import AES
for kn,K in (("K1",K1),("K2",K2)):
    def mk(K=K):
        def f(s):
            blk=struct.pack(">Q",0)+struct.pack(">Q",s)  # 0||sec
            ct=AES.new(K,AES.MODE_ECB).encrypt(blk)
            words=struct.unpack(">4I",ct)
            return pack_be(w&0x7fffffff for w in words)
        return f
    add("aesecb_%s_mask"%kn,mk())

# mt19937
class MT:
    def __init__(self,seed):
        self.mt=[0]*624; self.idx=624
        self.mt[0]=seed&0xffffffff
        for i in range(1,624):
            self.mt[i]=(1812433253*(self.mt[i-1]^(self.mt[i-1]>>30))+i)&0xffffffff
    def gen(self):
        if self.idx>=624:
            for i in range(624):
                y=(self.mt[i]&0x80000000)+(self.mt[(i+1)%624]&0x7fffffff)
                self.mt[i]=self.mt[(i+397)%624]^(y>>1)^(0x9908b0df if y&1 else 0)
            self.idx=0
        y=self.mt[self.idx]; self.idx+=1
        y^=y>>11; y^=(y<<7)&0x9d2c5680; y^=(y<<15)&0xefc60000; y^=y>>18
        return y&0xffffffff
def mt_model(s):
    g=MT(s)
    return pack_be(g.gen()&0x7fffffff for _ in range(4))
add("mt19937_sec_be",mt_model)

# rand_r (bionic/glibc): state=state*1103515245+12345; ret=(state>>16)&0x7fff? variants
def rand_r_a(s):
    st=s&0x7fffffff; out=[]
    for _ in range(4):
        st=(st*1103515245+12345)&0x7fffffff
        out.append((st>>16)&0x7fff)
    return pack_be(out)
add("rand_r_a",rand_r_a)

hits=0
for name,f in models.items():
    if try_model(f,name): hits+=1
print("model battery done, hits:",hits)

# ---- brute force java Random(sec + C), C in +-5e6, using byte0 filter
MUL=0x5DEECE66D; ADD=0xB; MASK=(1<<48)-1
sec0,prefix0=items[0]
p0=prefix0[0]
found=[]
for C in range(-5000000,5000001):
    seed=(sec0+C)&((1<<48)-1)
    s=(seed^MUL)&MASK
    s=(s*MUL+ADD)&MASK
    out1=s>>17  # next(31)
    if (out1>>24)!=p0: continue
    # full check
    r=JR=C
    ss=(sec0+C)
    rr=(ss^MUL)&MASK
    vals=[]
    ok=True
    for i in range(4):
        rr=(rr*MUL+ADD)&MASK
        vals.append(rr>>17)
    if pack_be(vals)==prefix0:
        found.append(("plus",C))
        print("FOUND javaRandom seed=sec%+d"%C)
print("brute force done, found:",found)
