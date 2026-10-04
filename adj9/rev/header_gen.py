# header_gen.py - VERIFIED adj9 16-byte header generator (36/36 corpus, 2 devices)
# usage: make_header(unix_seconds) -> 16 bytes
import struct
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
        o=v>>1
        self.f=(self.f+1)%31; self.b=(self.b+1)%31
        return o
def make_header(unix_sec):
    R=Random3(unix_sec)
    d=[R.next() for _ in range(8)]
    w=[d[2*i]^d[2*i+1] for i in range(4)]
    return b"".join(struct.pack(">I",x) for x in w)
if __name__=="__main__":
    import sys
    sec=int(sys.argv[1])
    print(make_header(sec).hex())
