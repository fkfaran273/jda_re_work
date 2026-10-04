#!/usr/bin/env python3
import sys
sys.path.insert(0,'.')
from _fold_exact import data, secs
def va2off(va):
    for nm,(a,o,s) in secs.items():
        if s and a<=va<a+s: return o+(va-a),nm
    return None,None
def score(b):
    return sum(1 for c in b if 32<=c<127)
def best(va,label,maxn=120):
    o,nm=va2off(va)
    if o is None: print("  0x%06x %-14s <no section>"%(va,label)); return
    e=data.index(b'\0',o); raw=data[o:min(e,o+maxn)]
    if len(raw)<3: print("  0x%06x %-14s <short> %s"%(va,label,raw.hex())); return
    bestk,bests=None,-1
    for k in range(256):
        d=bytes(c^k for c in raw)
        s=score(d)
        if s>bests: bests,bestk=s,k
    d=bytes(c^bestk for c in raw)
    print("  0x%06x %-12s [%s] key=0x%02x  %r"%(va,label,nm,bestk,d[:100]))
for va,l in [(0x155000,'csv'),(0x154920,'e28e4'),(0x154938,'e490c'),
             (0x155138,'urandom'),(0x155db8,'e2978'),(0x155dc8,'bss'),
             (0x155dac,'bss'),(0x155e30,'bss'),(0x154900,'x'),(0x154940,'x2'),
             (0x154960,'x3'),(0x1549a0,'x4'),(0x1549e0,'x5'),(0x154a20,'x6')]:
    best(va,l)
