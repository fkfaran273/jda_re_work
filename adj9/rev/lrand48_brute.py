import re, glob, struct
rows=[]
for lf in glob.glob("cap/*.log"):
    data=open(lf,"rb").read().decode("utf-8","ignore")
    for m in re.finditer(r"--- (\d+) t0=(\d+) t1=(\d+) ms=\d+ sec=(\d+) len=192\n([0-9a-f]{384})", data):
        rows.append((int(m.group(4)), int(m.group(2)), bytes.fromhex(m.group(5))))
seen={}
for sec,t0,b in rows: seen.setdefault(sec,(t0,b[:16]))
items=list(seen.items())
M=1<<48; A=0x5DEECE66D; C=0xB
# For each observed header, solve for the LCG state directly!
# If header = 4 consecutive lrand48 outputs as BE32, then state sequence:
# x1 = (A*(seed48)+C) mod 2^48, out1 = x1>>17
# out1 is 31 bits = TOP 31 bits of x1. So x1 = (out1<<17) | unknown17.
# x2 = (A*x1+C) mod 2^48, out2 = x2>>17.
# Given out1..out4 we can recover the low 17 bits of x1 by brute force (2^17 = 131072 tries per blob!)
def solve(outs):
    o1,o2,o3,o4=outs
    x1hi=o1<<17
    for lo in range(1<<17):
        x1=x1hi|lo
        x2=(A*x1+C)&(M-1)
        if x2>>17!=o2: continue
        x3=(A*x2+C)&(M-1)
        if x3>>17!=o3: continue
        x4=(A*x3+C)&(M-1)
        if x4>>17!=o4: continue
        x0=((x1-C)*pow(A,-1,M))&(M-1)   # state before first draw
        seed48=x0  # if srand48: x0=(seed<<16)|0x330E
        if seed48 & 0xFFFF == 0x330E:
            seed=(seed48>>16)&0xffffffff
            return seed
        return ("raw",x0,seed48)
    return None
for sec,(t0,p) in items:
    outs=struct.unpack(">4I",p)
    r=solve(outs)
    print(sec, p.hex(), "->", r)
