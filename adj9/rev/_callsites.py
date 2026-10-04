#!/usr/bin/env python3
import sys, collections
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
insns=list(md.disasm(data[TO:TO+TS],TA))
byaddr={i.address:i for i in insns}

def win(center, back=0x60, fwd=0x10, label=""):
    print("==== %s  (center 0x%06x) ===="%(label,center))
    for i in insns:
        if center-back<=i.address<=center+fwd:
            mark="  <== CALL" if i.address==center else ""
            print("  0x%06x  %-8s %s%s"%(i.address,i.mnemonic,i.op_str,mark))
    print()

win(0x0e4318,0x80,0x0c,"0xe3148 -> syscall")
win(0x0e3c50,0x40,0x0c,"0xe3148 -> realloc")
win(0x0e2900,0x40,0x0c,"0xe26d4 -> timer_settime")
win(0x0e4bf0,0x40,0x0c,"0xe4b8c -> timer_settime")
win(0x0e2608,0x40,0x0c,"0xe2518 -> vsnprintf")
win(0x13dec0,0x40,0x0c,"0x13de98 -> pthread_once")
win(0x01c8b4,0x40,0x0c,"0x01c230 -> access")
