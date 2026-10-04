import re, glob, struct
rows=[]
for lf in glob.glob("cap/*.log"):
    data=open(lf,"rb").read().decode("utf-8","ignore")
    for m in re.finditer(r"--- (\d+) t0=(\d+) t1=(\d+) ms=\d+ sec=(\d+) len=192\n([0-9a-f]{384})", data):
        rows.append((int(m.group(4)), bytes.fromhex(m.group(5))))
seen={}
for sec,b in rows: seen.setdefault(sec,b[:16])
items=list(seen.items())

def rand_seq(seed,n):
    r=seed&M31 if (M31:=0x7fffffff) else 0
    out=[]
    for _ in range(n):
        hi,lo=divmod(r,127773)
        r=16807*lo-2836*hi
        if r<=0: r+=0x7fffffff
        out.append(r)
    return out

# Model A: whole 16B = 4 draws as LE u32 (v2 low first) with seed=s (srand(time))
# Model B: BE
def mA(s):
    vs=rand_seq(s,4)
    return b"".join(struct.pack("<I",v) for v in vs)
def mB(s):
    vs=rand_seq(s,4)
    return b"".join(struct.pack(">I",v) for v in vs)
# Model C: byte-at-a-time LE: v&0xff per draw ×16 (draws of low byte only)
def mC(s):
    vs=rand_seq(s,16)
    return bytes(v&0xff for v in vs)
# Model D: 8 draws of 16-bit (two u16 halves, BE within word?) - bionic rand is 31bit; 
# some code packs (v>>8)&0xffff etc. Try 8 draws of (v & 0xffff) BE16:
def mD(s):
    vs=rand_seq(s,8)
    return b"".join(struct.pack(">H",v&0xffff) for v in vs)
# Model E: 8 draws of ((v>>16)&0xffff) BE16
def mE(s):
    vs=rand_seq(s,8)
    return b"".join(struct.pack(">H",(v>>16)&0xffff) for v in vs)
# Model F: 16 draws of (v&0xf)?? nah.
hits=0
for name,fn in (("A_le4",mA),("B_be4",mB),("C_lo8x16",mC),("D_be16lo",mD),("E_be16hi",mE)):
    ok=0
    for sec,p in items:
        # seed unknown; try sec-d for d in 0..2 and sec+d
        for d in (0,1,-1,2,-2):
            if fn(sec+d)==p: ok+=1; break
    if ok: print("HIT",name,ok); hits+=1
print("hits:",hits,"/",len(items))

# Model G: the four u32s are INDEPENDENT rand draws? i.e., 0x12a2fc's fn is called
# 4 times with srand(sec) before each => same value each time? no, then all 4 words equal.
# Model H: seed differs per word: srand(time+i)? 
def mH(s):
    out=[]
    for i in range(4):
        vs=rand_seq(s+i,1)
        out.append(vs[0])
    return b"".join(struct.pack(">I",v) for v in out)
ok=0
for sec,p in items:
    if any(mH(sec+d)==p for d in (0,1,-1)): ok+=1
print("H (seed+i):",ok)
