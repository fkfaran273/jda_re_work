# chain2.py — Java Random / xorshift chain tests on consecutive headers
import re,glob,struct,json
def parse_events(path):
    lines=open(path,encoding="utf-8",errors="replace").read().splitlines()
    ev=[];cur=None
    for ln in lines:
        m=re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\d+) ts=(\d+)",ln)
        if m:
            cur={"type":m.group(1),"ts":int(m.group(3)),"body":[]}
            ev.append(cur);continue
        if cur is not None:
            if ln.startswith("###ADJ9_END"):cur=None;continue
            cur["body"].append(ln)
    return ev
def field(e,name):
    j="\n".join(e["body"])
    m=re.search(r"(?:^|\s)"+name+r"=([^\s]+)",j,re.M)
    return m.group(1) if m else None
seqs={}
for path in glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/oracle_run*.log"):
    ev=parse_events(path)
    seq=[]
    for e in ev:
        if e["type"]=="nsign":
            h=field(e,"hex")
            if h: seq.append((e["ts"],h))
    if len(seq)>=2: seqs[path.split("\\")[-1]]=seq

def jrand_next(state):
    state=(state*0x5DEECE66D+0xB)&((1<<48)-1)
    return state
def jrand_output(state):
    return (state>>16)&0xFFFFFFFF  # nextInt()
M48=(1<<48)-1
print("=== Java Random chain: does w[i+1] = f(w[i])? ===")
# For a 32-bit output w, the possible predecessor states are w<<16 + k for k in 0..65535.
# If outputs are consecutive nextInt()s from one Random, then for some k,l: ((w0<<16|k)*A+C)&M48 == w1<<16|l
tot=0;hits=0
for k,seq in sorted(seqs.items()):
    for (t0,h0),(t1,h1) in zip(seq,seq[1:]):
        w0=struct.unpack(">4I",bytes.fromhex(h0)[:16])
        w1=struct.unpack(">4I",bytes.fromhex(h1)[:16])
        for i in range(4):
            hi=(w1[i]>>31)&1   # nextInt() bit31
            # brute force low 16 bits of predecessor: 65536 tries
            found=None
            for lo in range(65536):
                s0=(w0[i]<<16)|lo
                s1=jrand_next(s0)
                if (s1>>16)==w1[i]:
                    found=lo; break
            tot+=1
            if found is not None:
                hits+=1; print("  HIT",k,i,"lo16=%04x"%found)
print("Java Random: %d/%d"%(hits,tot))
# xorshift32
def xs32(x):
    x^=(x<<13)&0xFFFFFFFF; x^=x>>17; x^=(x<<5)&0xFFFFFFFF; return x
print("\n=== xorshift32 chain ===")
hits=0;tot=0
for k,seq in sorted(seqs.items()):
    for (t0,h0),(t1,h1) in zip(seq,seq[1:]):
        w0=struct.unpack(">4I",bytes.fromhex(h0)[:16])
        w1=struct.unpack(">4I",bytes.fromhex(h1)[:16])
        for i in range(4):
            tot+=1
            if xs32(w0[i])==w1[i]: hits+=1; print("  HIT",k,i)
print("xorshift32: %d/%d"%(hits,tot))
# xorshift64 on pairs of words
def xs64(x):
    x^=(x<<13)&0xFFFFFFFFFFFFFFFF; x^=x>>7; x^=(x<<17)&0xFFFFFFFFFFFFFFFF; return x
hits=0;tot=0
for k,seq in sorted(seqs.items()):
    for (t0,h0),(t1,h1) in zip(seq,seq[1:]):
        w0=struct.unpack(">4I",bytes.fromhex(h0)[:16])
        w1=struct.unpack(">4I",bytes.fromhex(h1)[:16])
        for i in range(3):
            x=(w0[i]<<32)|w0[i+1]
            y=(w1[i]<<32)|w1[i+1]
            tot+=1
            if xs64(x)==y: hits+=1; print("  HIT64",k,i)
print("xorshift64: %d/%d"%(hits,tot))
# PCG? test pcg32 simple output = xorshift-high+rotation... skip, test WELL later if needed
# Check the repeated-header case
print("\n=== repeated header context ===")
for k,seq in sorted(seqs.items()):
    for idx,(ts,h) in enumerate(seq):
        if h[:32]=="6b6dcc317c207d15139bc3c472deff54":
            print(k,"idx",idx,"ts",ts)
