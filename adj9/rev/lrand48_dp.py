import re, glob, struct
rows=[]
for lf in glob.glob("cap/*.log"):
    data=open(lf,"rb").read().decode("utf-8","ignore")
    for m in re.finditer(r"--- (\d+) t0=(\d+) t1=(\d+) ms=\d+ sec=(\d+) len=192\n([0-9a-f]{384})", data):
        rows.append((int(m.group(4)), bytes.fromhex(m.group(5))))
seen={}
for sec,b in rows: seen.setdefault(sec,b[:16])
items=list(seen.items())
M=1<<48; A=0x5DEECE66D; C=0xB
AINV=pow(A,-1,M)
def adv(x): return (A*x+C)&(M-1)

def solve(outs, G=8, endian="be"):
    if endian=="be": targets=list(struct.unpack(">4I",outs))
    else: targets=list(struct.unpack("<4I",outs))
    sols=[]
    # X1 = state that produced target[0]: X1>>17 == t0
    stack=[(targets[0]<<17, 1, [])]  # (state, next_target_idx, gaps)
    while stack:
        x,ti,gaps=stack.pop()
        if ti==len(targets):
            sols.append((x,gaps))
            continue
        y=x; gap=0
        while gap<G:
            y=adv(y); gap+=1
            if y>>17==targets[ti]:
                stack.append((y,ti+1,gaps+[gap]))
    return sols

found_any=False
for endian in ("be","le"):
    for sec,p in items:
        sols=solve(p,8,endian)
        for x,gaps in sols[:4]:
            # walk back up to 40 steps looking for srand48 signature (low16==0x330E)
            back=x; k=0; seedhit=None
            for k in range(1,40):
                back=((back-C)*AINV)&(M-1)
                if back&0xFFFF==0x330E:
                    seedhit=((back>>16)&0xffffffff,k)
                    break
            print(endian,sec,"gaps",gaps,"seedhit",seedhit)
            if seedhit: found_any=True
print("any seed hits:",found_any)
