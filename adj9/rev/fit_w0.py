"""fit_w0.py - can any known 32-bit mixer map V to the first region word W0
(or to d2 / d4 words)?  W0 is a single avalanche word, the easiest handle."""
import struct, sys, os, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fit_table as F
M32=0xFFFFFFFF; M64=0xFFFFFFFFFFFFFFFF

def fmix32(h):
    h&=M32; h^=h>>16; h=(h*0x85ebca6b)&M32; h^=h>>13; h=(h*0xc2b2ae35)&M32; h^=h>>16; return h
def fmix64(h):
    h&=M64; h^=h>>33; h=(h*0xff51afd7ed558ccd)&M64; h^=h>>33; h=(h*0xc4ceb9fe1a85ec53)&M64; h^=h>>33; return h
def wang(h):
    h=(~h+(h<<15))&M32; h^=h>>12; h=(h+(h<<2))&M32; h^=h>>4; h=(h*2057)&M32; h^=h>>16; return h
def splitmix32(h):
    h=(h+0x9e3779b9)&M32; z=h; z=((z^(z>>16))*0x21f0aaad)&M32; z=((z^(z>>15))*0x735a2d97)&M32; return (z^(z>>15))&M32
def murmur3_x86_32(data,seed=0):
    import ctypes
    c1,c2=0xcc9e2d51,0x1b873593; h=seed&M32; l=len(data)
    for i in range(0,l//4*4,4):
        k=int.from_bytes(data[i:i+4],'little'); k=(k*c1)&M32; k=((k<<15)|(k>>17))&M32; k=(k*c2)&M32
        h^=k; h=((h<<13)|(h>>19))&M32; h=(h*5+0xe6546b64)&M32
    k=0; r=l&3
    if r>=3: k^=data[l-1]<<16
    if r>=2: k^=data[l-2]<<8
    if r>=1: k^=data[l-3]
    if r>=1:
        k=(k*c1)&M32; k=((k<<15)|(k>>17))&M32; k=(k*c2)&M32; h^=k
    h^=l; h=fmix32(h); return h
def xxh32(data,seed=0):
    P1,P2,P3,P4,P5=0x9E3779B1,0x85EBCA77,0xC2B2AE3D,0x27D4EB2F,0x165667B1
    l=len(data); i=0
    if l>=16:
        v1=(seed+P1+P2)&M32; v2=(seed+P2)&M32; v3=seed&M32; v4=(seed-P1)&M32
        while i<=l-16:
            for vi in range(4):
                k=int.from_bytes(data[i:i+4],'little'); i+=4
                if vi==0: v1=(v1+(k*P2))&M32; v1=((v1<<13)|(v1>>19))&M32; v1=(v1*P1)&M32
                elif vi==1: v2=(v2+(k*P2))&M32; v2=((v2<<13)|(v2>>19))&M32; v2=(v2*P1)&M32
                elif vi==2: v3=(v3+(k*P2))&M32; v3=((v3<<13)|(v3>>19))&M32; v3=(v3*P1)&M32
                else: v4=(v4+(k*P2))&M32; v4=((v4<<13)|(v4>>19))&M32; v4=(v4*P1)&M32
        h=(((v1<<1)|(v1>>31))+((v2<<7)|(v2>>25))+((v3<<12)|(v3>>20))+((v4<<18)|(v4>>14)))&M32
    else:
        h=(seed+P5)&M32
    h=(h+l)&M32
    while i<=l-4:
        k=int.from_bytes(data[i:i+4],'little'); k=(k*P3)&M32; k=((k<<17)|(k>>15))&M32; k=(k*P4)&M32
        h^=k; h=(((h<<13)|(h>>19))&M32); h=(h*5+0xe6546b64)&M32; i+=4
    while i<l:
        h^=data[i]*P5; h=(((h<<11)|(h>>21))&M32); h=(h*P1)&M32; i+=1
    h^=h>>15; h=(h*P2)&M32; h^=h>>13; h=(h*P3)&M32; h^=h>>16; return h

rows=F.dedup(F.load_all()); seen=set(); uniq=[]
for r in rows:
    k=(r['V'],r['pid'],r['tid'])
    if k not in seen: seen.add(k); uniq.append(r)
rows=uniq
print("rows",len(rows))
# candidate value functions
mixers={
 'fmix32':lambda V,p,t: fmix32(V),
 'fmix32(p^t^V)':lambda V,p,t: fmix32(V^p^t),
 'fmix64lo':lambda V,p,t: fmix64(V)&M32,
 'fmix64(V<<32|pt)':lambda V,p,t: fmix64((V<<32)|((p<<16)|t))&M32,
 'wang32':lambda V,p,t: wang(V),
 'splitmix32':lambda V,p,t: splitmix32(V),
 'murmur3(Vle)':lambda V,p,t: murmur3_x86_32(struct.pack('<I',V&M32)),
 'murmur3(Vbe)':lambda V,p,t: murmur3_x86_32(struct.pack('>I',V&M32)),
 'xxh32(Vle)':lambda V,p,t: xxh32(struct.pack('<I',V&M32)),
 'xxh32(Vbe)':lambda V,p,t: xxh32(struct.pack('>I',V&M32)),
 'sha256(V)[0:4]':lambda V,p,t: int.from_bytes(hashlib.sha256(struct.pack('>I',V&M32)).digest()[:4],'big'),
 'sha256(V)[::-4]':lambda V,p,t: int.from_bytes(hashlib.sha256(struct.pack('<I',V&M32)).digest()[:4],'big'),
}
# also: W0 for a seed-scan over additive constants is too big; test whether
# W0 has ANY bit-linear relation to V via GF(2) (avalanche kills it, but check)
targets={'W0':lambda r:r['w0'][0],'d2':lambda r:r['d2w'],'d4_0':lambda r:r['d4w'][0],'d4_6':lambda r:r['d4w'][6]}
for mn,mf in mixers.items():
    for tn,tf in targets.items():
        hit=sum(1 for r in rows if mf(r['V'],r['pid'],r['tid'])==tf(r))
        if hit: print("HIT",mn,tn,hit,"/",len(rows))
print("mixer scan done (any HIT line above = candidate).")
# R (from d4[6]>>16) vs V?
for r in rows[:3]:
    print("  V=%08x W0=%08x d2=%08x d4_6>>16=%04x"%(r['V'],r['w0'][0],r['d2w'],r['d4w'][6]>>16))
