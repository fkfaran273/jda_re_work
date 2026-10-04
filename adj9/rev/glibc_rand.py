# glibc_rand.py — bionic rand() is NOT lrand48 on Android! Check actual AOSP source:
# bionic/libc/bionic/rand.cpp:
#   int rand() { return arc4random()? NO. Actual AOSP: rand() = lrand48()? Verify.
# Actually AOSP rand.cpp: "int rand() { return lrand48(); }" — but older devices/musl differ.
# ALSO: glibc rand() = random() TYPE_3 additive feedback (not lrand48!).
# Android's bionic uses arc4random for rand() since... NO. Check both:
# Model 1: glibc random() TYPE_3 (what glibc rand() actually is)
# Model 2: bionic lrand48
# Test BOTH against Fiddler + moto corpus with all combiners.
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

# ---- glibc TYPE_3 random() ----
DEG_3=31; SEP_3=3
def glibc_srandom_r(seed):
    # int32_t with wraparound
    def s32(x): x&=0xFFFFFFFF; return x-(1<<32) if x>=0x80000000 else x
    state=[0]*34
    state[0]=seed & 0xFFFFFFFF if seed>=0 else s32(seed)
    if state[0]==0: state[0]=1
    prev=state[0]
    for i in range(1,10):
        # word = 16807*prev % 2147483647 via Schrage, signed
        hi=prev>>16
        lo=prev&0xFFFF
        word=16807*lo-2836*hi
        if word<0: word+=2147483647
        prev=word
        state[i]=prev
    for i in range(2,10):  # glibc: state[i] (i=2..9) = 16807*state[i-1]... then
        pass
    # full glibc __srandom_r:
    state[0]=seed if seed!=0 else 1
    state[0]&=0xFFFFFFFF
    if state[0]>=0x80000000: state[0]-=1<<32
    prev=state[0]
    for i in range(1,10):
        word=s32(16807*prev)
        word=s32(word)
        # Schrage
        hi=prev>>16 if prev>=0 else -((-prev)>>16)
        lo=prev&0xFFFF
        word=16807*lo-2836*hi
        if word<0: word+=2147483647
        prev=word
        state[i]=word
    state[10]=state[0]
    for i in range(11,34):
        state[i]=s32(state[i-3]+state[i-31])   # wait: r_new = r_old[i-3] + r_old[i-31]
    # fptr= &state[3], rptr = &state[0]? glibc: fptr=&randtbl[3]... after init: fptr SEP_3 ahead
    fptr,rptr=3,0
    out=[]
    f_i,r_i=3,0
    for _ in range(310):  # discard 310
        new=s32(state[f_i]+state[r_i])
        state[f_i]=new
        out.append((new>>1)&0x7FFFFFFF)
        f_i=(f_i+1)%34
        r_i=(r_i+1)%34
    outs=[]
    for _ in range(200):
        new=s32(state[f_i]+state[r_i])
        state[f_i]=new
        outs.append((new>>1)&0x7FFFFFFF)
        f_i=(f_i+1)%34
        r_i=(r_i+1)%34
    return outs
hits=0
for p in P[:10]:
    done=False
    for lbl in ("sec_in","sec_out"):
        if p[lbl] is None: continue
        for d in (-1,0,1):
            sd=(p[lbl]+d)&0xFFFFFFFF
            st=glibc_srandom_r(sd)
            for k in range(60):
                cands={
                 "raw":st[k:k+4],
                 "xorD":[st[k+2*i]^st[k+2*i+1] for i in range(4)],
                 "xorO":[st[k+i]^st[k+i+1] for i in range(4)],
                }
                for nm,w in cands.items():
                    if tuple(w)==p["w"]:
                        print("GLIBC-HIT %s %s%+d k=%d %s"%(p["h"][:16],lbl,d,k,nm))
                        hits+=1;done=True;break
                if done:break
            if done:break
        if done:break
print("glibc TYPE_3 hits:",hits)
