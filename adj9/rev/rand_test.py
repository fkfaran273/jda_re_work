import re, glob, struct
from collections import defaultdict
rows=[]
for lf in glob.glob("cap/*.log"):
    data=open(lf,"rb").read().decode("utf-8","ignore")
    for m in re.finditer(r"--- (\d+) t0=(\d+) t1=(\d+) ms=\d+ sec=(\d+) len=192\n([0-9a-f]{384})", data):
        rows.append((int(m.group(4)), bytes.fromhex(m.group(5))))
seen={}
for sec,b in rows: seen.setdefault(sec,b[:16])
items=list(seen.items())
# bionic rand() pre-N: r = r*16807 % 2147483647 (Schrage). state type long.
# outputs are 31-bit positive.
M31=0x7fffffff
def rand_seq(seed,n):
    r=seed&M31
    out=[]
    for _ in range(n):
        # Schrage: hi=r/127773, lo=r%127773; r=16807*lo-2836*hi; if r<=0 r+=M31
        hi,lo=divmod(r,127773)
        r=16807*lo-2836*hi
        if r<=0: r+=M31
        out.append(r)
    return out
def pack_be(vs): return b"".join(struct.pack(">I",v) for v in vs)
hits=0
for seedname,seedfn in (("sec",lambda s,t:s),("t0",lambda s,t:t)):
    for skip in (0,1,2,4,8):
        ok=0
        for sec,p in items:
            seed=seedfn(sec,sec)
            vs=rand_seq(seed,skip+4)[skip:]
            if pack_be(vs)==p: ok+=1
        if ok: print("HIT",seedname,"skip",skip,":",ok); hits+=1
# Also test C rand with srand(time(NULL)) where the time at signing differs from
# our sec label by delta 0..120 (device boots, clock drift). Try per-blob search
# seed = any 31-bit value producing the observed 4-tuple directly (state IS r).
# Brute: r1=first output. If state==output, seed=outs[0], then r2..r4 must follow.
def test_state_eq_out(p):
    vs=struct.unpack(">4I",p)
    r=vs[0]
    for v in vs[1:]:
        hi,lo=divmod(r,127773)
        r=16807*lo-2836*hi
        if r<=0: r+=M31
        if r!=v: return False
    return True
ok=sum(1 for sec,p in items if test_state_eq_out(p))
print("state==out model:",ok,"/",len(items))
# What about the whole 16B produced by ONE rand() as 31 bits + ... no.
# Test: 16 bytes = 8 draws of (v & 0xffff) pairs BE16
def model_16b(seed,n):
    return [v&0xffff for v in rand_seq(seed,n)]
ok=0
for sec,p in items:
    vs=model_16b(sec,8)
    if struct.pack(">8H",*vs)==p: ok+=1
print("16b halves:",ok,"/",len(items))
print("battery done hits:",hits)
