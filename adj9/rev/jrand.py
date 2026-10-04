import re, glob, struct
MASK48=(1<<48)-1
MUL=0x5DEECE66D
ADD=0xB
class JR:
    def __init__(self, seed):
        self.s=(seed ^ MUL) & MASK48
    def next(self, bits):
        self.s=(self.s*MUL+ADD)&MASK48
        r=self.s>>(48-bits)
        return r
    def next31(self):
        return self.next(31)

# rapid row 0: t0=1788956305996 sec=1788956305 prefix=2723cdaf3b6f19727fb0ce8b5410bc10
targets={
 1788956305: bytes.fromhex("2723cdaf3b6f19727fb0ce8b5410bc10"),
}
# collect more: all rapid rows -> sec -> prefix (first occurrence)
rows=[]
for lf in glob.glob("cap/*.log"):
    data=open(lf,"rb").read().decode("utf-8","ignore")
    for m in re.finditer(r"--- (\d+) t0=(\d+) t1=(\d+) ms=\d+ sec=(\d+) len=192\n([0-9a-f]{384})", data):
        rows.append((int(m.group(4)), int(m.group(2)), bytes.fromhex(m.group(5))))
seen={}
for sec,t0,b in rows:
    seen.setdefault(sec,(t0,b[:16]))
print("sample secs:",len(seen))
def try_seed(seed, prefix):
    r=JR(seed)
    v=b"".join(struct.pack(">I", r.next31()) for _ in range(4))
    return v==prefix
# search seeds: sec, sec-ms variants +- 2
hit=0
for sec,(t0,prefix) in seen.items():
    found=None
    for d in range(-3,4):
        cands=[sec+d, t0+d, t0+d*1000]
        # also seconds in milliseconds as seed
        for c in cands:
            if try_seed(c, prefix):
                found=("sec",c); break
        if found: break
    if found: hit+=1
    print(sec, "prefix", prefix.hex(), "match:", found)
print("hits:",hit,"/",len(seen))
