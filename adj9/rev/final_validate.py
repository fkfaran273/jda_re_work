import base64, struct, json
M31=2147483647
class Random3:
    __slots__=("r","f","b")
    def __init__(self, seed):
        r=self.r=[0]*31
        s=seed & 0xFFFFFFFF
        if s==0: s=1
        w=s if s<2**31 else s-2**32
        r[0]=w; prev=w
        for i in range(1,31):
            hi=prev//127773 if prev>=0 else -((-prev)//127773); lo=prev-hi*127773
            word=16807*lo-2836*hi
            if word<0: word+=M31
            prev=word; r[i]=word
        self.f=3; self.b=0
        for _ in range(310): self.next()
    def next(self):
        v=(self.r[self.f]+self.r[self.b])&0xFFFFFFFF
        self.r[self.f]=v if v<2**31 else v-2**32
        o=v>>1
        self.f=(self.f+1)%31; self.b=(self.b+1)%31
        return o
def make_header(sec):
    R=Random3(sec)
    d=[R.next() for _ in range(8)]
    w=[d[2*i]^d[2*i+1] for i in range(4)]
    return b"".join(struct.pack(">I",x) for x in w)
bs=json.load(open("blobset.json"))
hits=0; total=len(bs); msb_fail=0
miss=[]
for e in bs:
    raw=bytes.fromhex(e["hex"])
    hdr=raw[:16]
    for off in (0,4,8,12):
        if hdr[off]>=0x80: msb_fail+=1
    sec=e["ts"]//1000
    ok=any(make_header(c)==hdr for c in (sec,sec-1,sec-2,sec+1))
    if ok: hits+=1
    else: miss.append((e["ts"],hdr.hex()))
print("blobset header match %d/%d msb_viol=%d" % (hits,total,msb_fail))
for m in miss[:5]: print("MISS",m)
sigs=json.load(open("saz_sigs.json"))
bodies=[base64.b64decode(x["sig_b64"])[16:] for x in sigs]
const=sum(1 for i in range(176) if len(set(b[i] for b in bodies))==1)
print("SAZ body constant positions:",const,"/176")
print("SAZ lens:",[len(base64.b64decode(x["sig_b64"])) for x in sigs])
print("blob lens:",set(len(bytes.fromhex(e["hex"])) for e in bs))
