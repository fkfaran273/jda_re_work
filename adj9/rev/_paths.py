#!/usr/bin/env python3
import sys
sys.path.insert(0,'.')
from _fold_exact import data, secs
def va2off(va):
    for nm,(a,o,s) in secs.items():
        if s and a<=va<a+s and nm!='.bss': return o+(va-a)
    return None
def show(va,label=""):
    o=va2off(va)
    if o is None: print("  0x%06x %-14s <no section>"%(va,label)); return
    e=data.index(b'\0',o); raw=data[o:e+1]
    if not raw: print("  0x%06x %-14s <empty>"%(va,label)); return
    k=raw[-1]
    dec=bytes(b^k for b in raw[:-1])
    print("  0x%06x %-14s key=0x%02x raw=%s"%(va,label,k,raw[:40].hex()))
    print("        -> %r"%(dec[:60]))
for va,lab in [(0x155dac,'e1f88 path'),(0x154938,'e490c p1'),(0x155dc8,'e490c p2'),
               (0x155e30,'13e764 p'),(0x155138,'urandom?'),(0x155db8,'e2978 adr'),
               (0x154920,'e28e4 fmt'),(0x155000,'page155'),
               (0x14da88,'got-syscall-va'),(0x155d18,'?')]:
    show(va,lab)
